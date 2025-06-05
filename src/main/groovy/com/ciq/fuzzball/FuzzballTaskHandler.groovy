package com.ciq.fuzzball

import groovy.transform.CompileStatic
import groovy.transform.Canonical
import groovy.util.logging.Slf4j

import nextflow.Session
import nextflow.fusion.FusionAwareTask
import nextflow.processor.TaskRun
import nextflow.processor.TaskHandler
import static nextflow.processor.TaskStatus.*
import nextflow.executor.BashWrapperBuilder
import nextflow.trace.TraceRecord
import nextflow.util.ProcessHelper
import nextflow.exception.ProcessException
import java.nio.file.Path

import com.ciq.fuzzball.api.WorkflowServiceApi
import com.ciq.fuzzball.model.*

//TODO: should we be using grid tasks? how about task arrays?
//TODO: error handling
//TODO: credential refreshing?
//TODO: parse volumes from current fuzzball workflow

@Slf4j
@CompileStatic
class FuzzballTaskHandler extends TaskHandler implements FusionAwareTask {

    private final Path exitFile
    private final Long wallTimeMillis
    private final Path wrapperFile
    private final Path outputFile
    private final Path errorFile
    private volatile String wfId
    private boolean destroyed
    private FuzzballExecutor executor
    private WorkflowServiceApi fuzzballWfService
    private String wfDefinitionYaml
    private Session session

    FuzzballTaskHandler(TaskRun task, FuzzballExecutor executor) {
        super(task)
        // create the task handler
        this.exitFile = task.workDir.resolve(TaskRun.CMD_EXIT)
        this.outputFile = task.workDir.resolve(TaskRun.CMD_OUTFILE)
        this.errorFile = task.workDir.resolve(TaskRun.CMD_ERRFILE)
        this.wrapperFile = task.workDir.resolve(TaskRun.CMD_RUN)
        this.wallTimeMillis = task.config.getTime()?.toMillis()
        this.executor = executor
        this.session = executor.session
        this.fuzzballWfService = executor.fuzzballWfService
    }

    @Override
    void submit() {
        // create the wrapper
        buildTaskWrapper()

        // create a fuzzball workflow definition for the task
        TaskRun task = this.task
        WorkflowDefinitionJob job = FuzzballWorkflowDefinitionJobFactory.create(task, executor)
        WorkflowDefinition wfDef = new WorkflowDefinition(
            version: 'v1',
            volumes: executor.volumes,
            jobs: [(job.getName()): job],
        )
        FuzzballYaml yaml = new FuzzballYaml()
        wfDefinitionYaml = yaml.dump(wfDef)
        log.debug(wfDefinitionYaml)
        StartWorkflowRequest wfReq = new StartWorkflowRequest(
            name: "nf-${session.runName}-${job.getName()}",
            definition: wfDef,
        )

        // start the workflow
        WorkflowIDResponse wfIdResp = this.fuzzballWfService.startWorkflow(wfReq)
        this.wfId = wfIdResp.id

        status = SUBMITTED
    }

    protected void buildTaskWrapper() {
        final wrapper = fusionEnabled()
                ? fusionLauncher()
                : new BashWrapperBuilder(task.toTaskBean())
        // create the bash command wrapper and store in the task work dir
        wrapper.build()
    }

    /**
     * Check if the submitted job has started - i think this only handles transition from submitted to running
     */
    @Override
    boolean checkIfRunning() {
        if (!isSubmitted() || !wfId) {
            return false
        }

        GetWorkflowStatusResponse statusResp = fuzzballWfService.getWorkflowStatus(wfId)
        switch(statusResp.workflowStatus) {
            case WorkflowStatus.STAGE_STATUS_UNSPECIFIED -> false
            case WorkflowStatus.STAGE_STATUS_STARTED,
                 WorkflowStatus.STAGE_STATUS_FINISHED,
                 WorkflowStatus.STAGE_STATUS_FAILED,
                 WorkflowStatus.STAGE_STATUS_CANCELED -> {
                    status = RUNNING
                    yield true
            }
            default -> {
                log.warn("Unknown workflow status: ${statusResp.workflowStatus}")
                yield false
            }
        }
    }

    /**
     * Check if the submitted job has terminated its execution
     */
    @Override
    boolean checkIfCompleted() {

        if( !isRunning() ) { return false }

        GetWorkflowStatusResponse statusResp = fuzzballWfService.getWorkflowStatus(wfId)
        switch(statusResp.workflowStatus) {
            case WorkflowStatus.STAGE_STATUS_UNSPECIFIED,
                 WorkflowStatus.STAGE_STATUS_STARTED -> false
            case WorkflowStatus.STAGE_STATUS_FINISHED,
                 WorkflowStatus.STAGE_STATUS_FAILED -> {
                    status = COMPLETED
                    int exit = readExitFile()
                    task.exitStatus = exit
                    task.stdout = outputFile
                    task.stderr = errorFile
                    yield true
            }
            case WorkflowStatus.STAGE_STATUS_CANCELED -> {
                    status = COMPLETED
                    task.exitStatus = Integer.MAX_VALUE
                    task.stdout = outputFile
                    task.stderr = errorFile
                    yield true
            }
            default -> {
                log.warn("Unknown workflow status: ${statusResp.workflowStatus}")
                yield false
            }
        }
    }

    protected int readExitFile() {
        try {
            exitFile.text as Integer
        }
        catch( Exception e ) {
            log.debug "[Fuzzball Executor] Cannot read exitstatus for task: `$task.name` | ${e.message}"
            return Integer.MAX_VALUE
        }
    }

    /**
     * Force the submitted job to quit
     */
    @Override
    protected void killTask() {
        if( !wfId ) return
        fuzzballWfService.stopWorkflow(wfId)
        log.trace("Killing workflow with id: ${wfId}")
    }

    /**
     * @return An {@link nextflow.trace.TraceRecord} instance holding task runtime information
     */
    @Override
    TraceRecord getTraceRecord() {
        final result = super.getTraceRecord()
        if( wfId )
            result.put('native_id', wfId)
        return result
    }

}
