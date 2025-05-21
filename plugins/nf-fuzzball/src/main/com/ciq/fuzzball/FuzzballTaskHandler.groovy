package com.ciq.fuzzball

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import nextflow.fusion.FusionAwareTask
import nextflow.processor.TaskRun
import nextflow.processor.TaskHandler
import nextflow.processor.TaskStatus
import nextflow.executor.BashWrapperBuilder
import nextflow.exception.AbortOperationException

import java.nio.file.Paths
import java.nio.file.Path

import com.ciq.fuzzball.api.WorkflowServiceApi

//TODO: should this implement TaskArrayExecutor ?
@Slf4j
@CompileStatic
class FuzzballTaskHandler extends TaskHandler implements FusionAwareTask {

    private FuzzballExecutor executor
    private final Path exitFile
    private final Path wrapperFile
    private final Path outputFile
    private final Path errorFile
    private final Path logFile
    private final Path scriptFile
    private final Path inputFile
    private final Path traceFile
    protected volatile String jobId
    protected String currentStatus

    FuzzballTaskHandler(TaskRun task, FuzzballExecutor executor) {
        super(task)
        this.executor = executor
        this.logFile = task.workDir.resolve(TaskRun.CMD_LOG)
        this.scriptFile = task.workDir.resolve(TaskRun.CMD_SCRIPT)
        this.inputFile =  task.workDir.resolve(TaskRun.CMD_INFILE)
        this.outputFile = task.workDir.resolve(TaskRun.CMD_OUTFILE)
        this.errorFile = task.workDir.resolve(TaskRun.CMD_ERRFILE)
        this.exitFile = task.workDir.resolve(TaskRun.CMD_EXIT)
        this.wrapperFile = task.workDir.resolve(TaskRun.CMD_RUN)
        this.traceFile = task.workDir.resolve(TaskRun.CMD_TRACE)
    }

    @Override
    void submit() {

        log.info "[Fuzzball Executor] WorkDir: ${task.workDir.toString()}"
        status = TaskStatus.SUBMITTED
        // here we assemble a fuzzball workflow definition and submit it to the fuzzball api)
    }


    @Override
    boolean checkIfRunning() {
        if(!jobId || !isSubmitted()) {
            return false
        }
        return true

    }

    @Override
    boolean checkIfCompleted() {
        assert jobId
        if ( !isRunning()) {
            return false
        }
        return true

    }

    @Override
    void killTask() {
        assert jobId
        log.trace "[Fuzzball Executor] Killing Job $jobId"
        //stopJob(jobId)
    }

}