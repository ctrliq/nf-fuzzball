package com.ciq.fuzzball

import java.nio.file.Path

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j

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

// TODO: throttling
// TODO: implements TaskArrayExecutor ?

@Slf4j
@ServiceName(value='fuzzball-executor')
@CompileStatic
class FuzzballExecutor extends Executor implements ExtensionPoint {

    protected ApiConfig fuzzballApiConfig

    @Override
    protected void register() {
        super.register()
        //TODO: get context name from nextflow config fuzzball scope instead of the default activeContext from fuzzball config file
        this.fuzzballApiConfig = ApiConfig.fromFuzzballConfig()
    }

    /**
     * Submit the specified task for execution to the underlying system
     * and add it to the queue of tasks to be monitored.
     *
     * @param task A {@code TaskRun} instance
     */
    void submit( TaskRun task ) {
        log.trace "Scheduling process: ${task}"

        if( session.isTerminated() ) {
            new IllegalStateException("Session terminated - Cannot add process to execution queue: ${task}")
        }

        final handler = createTaskHandler(task)

        /*
         * Add the task to the queue for processing
         * Note: queue is implemented as a fixed size blocking queue, when
         * there's not space the *put* operation will block until some other tasks finish
         */
        monitor.schedule(handler)
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
        return TaskPollingMonitor.create(session, name, 1000, Duration.of('10 sec'))
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
