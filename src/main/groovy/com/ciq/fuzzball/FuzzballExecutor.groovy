package com.ciq.fuzzball

import java.nio.file.Path

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import groovy.json.JsonSlurper

import nextflow.exception.AbortOperationException
import nextflow.executor.Executor
import nextflow.file.FileHelper
import nextflow.processor.TaskHandler
import nextflow.processor.TaskMonitor
import nextflow.processor.TaskPollingMonitor
import nextflow.processor.TaskRun
import nextflow.util.Duration
import nextflow.util.ServiceName
import org.pf4j.ExtensionPoint

import com.ciq.fuzzball.api.ApiConfig
import com.ciq.fuzzball.api.WorkflowServiceApi
import com.ciq.fuzzball.model.*

// TODO: throttling
// TODO: implements TaskArrayExecutor ?
// TODO: fusion?
// TODO: fail if not running in a Fuzzball environment

@Slf4j
@ServiceName(value='fuzzball')
@CompileStatic
class FuzzballExecutor extends Executor implements ExtensionPoint {

    protected ApiConfig fuzzballApiConfig
    protected String executorWfId = null
    protected String executorWfName = null
    protected WorkflowServiceApi fuzzballWfService
    protected Map<String, WorkflowDefinitionJobMount> mounts = [:]
    protected Map<String, Volume> volumes = [:]

    @Override
    protected void register() {
        super.register()

        String cfgFile = this.session.config.navigate('fuzzball.cfgFile') as String
        if (cfgFile != null) {
            this.fuzzballApiConfig = ApiConfig.fromFuzzballConfig(
                configFile: cfgFile.replaceFirst('^~', System.getProperty('user.home'))
            )
        } else {
            this.fuzzballApiConfig = ApiConfig.fromFuzzballConfig()
        }

        // get the volumes and mounts of the current workflow
        executorWfName = System.getenv('FB_JOB_NAME')
        executorWfId = System.getenv('FB_WORKFLOW_ID')
        if (!(executorWfName && executorWfId)) {
            throw new AbortOperationException('Controller job is not running as a fuzzball workflow')
        }
        fuzzballWfService = new WorkflowServiceApi(fuzzballApiConfig)
        Workflow wf = fuzzballWfService.getWorkflow(executorWfId)
        // Parse JSON from byte[] specification using JsonSlurper
        WorkflowDefinition wfDef = WorkflowDefinition.fromMap(
            new JsonSlurper().parseText(new String(wf?.specification, 'UTF-8')) as Map<String, Object>
        )
        if (!wfDef) {
            throw new AbortOperationException("Unable to load workflow definition for workflow: $executorWfName")
        }
        volumes = wfDef.volumes ?: [:]
        mounts = wfDef.jobs[executorWfName]?.mounts ?: [:]
    }

    /**
     * The path where scratch data is written for the current executor.
     *
     * @return The executor base work directory
     */
    @Override
    Path getWorkDir() {
        session.getWorkDir()
    }

    /**
     * The path where project bin directory are stored
     *
     * @return The executor base bin directory
     */
    @Override
    Path getBinDir() {
        return session.getBinDir()
    }

    /**
     * Temporary work directory relative to the executor work directory
     *
     * @return The temporary directory path
     */
    Path getTempDir( String name = null, boolean create = true ) {
        def path = FileHelper.createTempFolder(getWorkDir())
        if( name )
            path = path.resolve(name)

        if( !path.exists() && create && !path.mkdirs() )
            throw new IOException("Unable to create directory: $path -- Check file system permission" )

        return path
    }

    /**
     * @return Create a new instance of the {@code TaskQueueHolder} component
     */
    @Override
    protected TaskMonitor createTaskMonitor() {
        return TaskPollingMonitor.create(session, name, 1000, Duration.of('20 sec'))
    }

    /**
     * @return Create a new {@code TaskHandler} to manage the scheduling
     * actions for this task
     */
    @Override
    TaskHandler createTaskHandler(TaskRun task) {
        assert task
        assert task.workDir
        log.trace "[Fuzzball Executor] Launching process > ${task.name} -- work folder: ${task.workDirStr}"
        return new FuzzballTaskHandler(task, this)
    }

    /**
     * @return {@code true} whenever the containerization is managed by the executor itself
     */
    @Override
    boolean isContainerNative() {
        return true
    }

    /**
     * Determines which container engine settings in the nextflow config file
     * will be used by this executor e.g. {@code 'docker'}, {@code 'singularity'}, etc.
     *
     * When {@code null} is returned the setting for the current engine marked as 'enabled' will be used.
     *
     * @return
     *      {@code docker} when {#link #isContainerNative} is {@code true} and {@code null} otherwise
     *
     */
    @Override
    String containerConfigEngine() {
        return 'docker'
    }

    /**
     * @return {@code true} whenever the secrets handling is managed by the executing platform itself
     */
    @Override
    boolean isSecretNative() {
        return true // TODO: check if this really makes sense
    }

    /**
     * @return {@code true} when the executor uses fusion file system
     */
    @Override
    boolean isFusionEnabled() {
        // maybe fusion would be nice but it's not free/open source
        return false
    }

}
