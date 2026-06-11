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

import okhttp3.Authenticator

import com.ciq.fuzzball.api.ApiConfig
import com.ciq.fuzzball.api.ApiUtils
import com.ciq.fuzzball.api.WorkflowServiceApi
import com.ciq.fuzzball.model.FuzzballApiV4Workflow as Workflow
import com.ciq.fuzzball.model.FuzzballApiV4WorkflowDefinition as WorkflowDefinition
import com.ciq.fuzzball.model.FuzzballApiV4WorkflowDefinitionJobMount as WorkflowDefinitionJobMount
import com.ciq.fuzzball.model.FuzzballApiV4WorkflowDefinitionVolume as Volume

// TODO: task batching possibly with TaskArrayExecutor

@Slf4j
@ServiceName(value='fuzzball')
@CompileStatic
class FuzzballExecutor extends Executor implements ExtensionPoint {

    protected ApiConfig fuzzballApiConfig
    protected String executorWfId = null
    protected String executorWfName = null
    protected WorkflowServiceApi fuzzballWfService
    protected Map<String, WorkflowDefinitionJobMount> mounts = [:] // path-keyed mounts of persistent volumes
    protected Map<String, Volume> volumes = [:] // only persistent volumes

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
        String envRefreshToken = System.getenv('FUZZBALL_REFRESH_TOKEN')
        Authenticator authenticator = Authenticator.NONE
        if (envRefreshToken) {
            if (!fuzzballApiConfig.oidcServerURL || !fuzzballApiConfig.accountId) {
                log.warn('FUZZBALL_REFRESH_TOKEN is set but oidcServerURL or accountId is missing from the Fuzzball config — token refresh on 401 disabled')
            } else {
                log.info('FUZZBALL_REFRESH_TOKEN detected — token refresh on 401 enabled')
                authenticator = new FuzzballTokenRefresher(fuzzballApiConfig, envRefreshToken, ApiUtils.createRefreshClient())
            }
        }
        fuzzballWfService = new WorkflowServiceApi(fuzzballApiConfig, authenticator)
        Workflow wf
        try {
            wf = fuzzballWfService.getWorkflow(executorWfId)
        } catch (Exception e) {
            throw new AbortOperationException("Failed to retrieve workflow for ID: $executorWfId", e)
        }
        // Parse JSON from byte[] specification using JsonSlurper
        WorkflowDefinition wfDef = WorkflowDefinition.fromMap(
            new JsonSlurper().parseText(new String(wf?.specification, 'UTF-8')) as Map<String, Object>
        )
        if (!wfDef) {
            throw new AbortOperationException("Unable to load workflow definition for workflow: $executorWfName")
        }
        volumes = filterPersistentVolumes(wfDef.volumes ?: [:])
        Map<String, WorkflowDefinitionJobMount> allMounts = wfDef.jobs[executorWfName]?.mounts ?: [:]
        mounts = filterMounts(allMounts, volumes)
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
     * Using a low default queueSize of 20. Can be overridden by the user with the queueSize executor config option.
     * @return Create a new instance of the {@code TaskQueueHolder} component.
     */
    @Override
    protected TaskMonitor createTaskMonitor() {
        return TaskPollingMonitor.create(session, config, name, 20, Duration.of('20 sec'))
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

    /**
     * Keep only the persistent volumes of the enclosing workflow so they can be
     * re-declared in the per-task workflows. In a v4 workflow definition a volume
     * is persistent iff it sets use == 'persistent' or an explicit volume name.
     * Everything else (empty block, use == 'ephemeral', provisioner-backed volume
     * without a name) is ephemeral, scoped to the enclosing workflow, and cannot
     * be shared with task workflows.
     *
     * Only the fields needed to bind the existing volume (use, name) are copied;
     * ingress/egress and size must not be repeated in task workflows.
     *
     * Volumes that still carry a legacy v1 reference were not upgraded by the
     * server (e.g. an identity-scoped reference without an explicit name fetched
     * without identity context) and are skipped with a warning.
     */
    protected static Map<String, Volume> filterPersistentVolumes(Map<String, Volume> allVolumes) {
        Map<String, Volume> filtered = [:]
        allVolumes.each { String name, Volume vol ->
            if (vol.reference) {
                log.warn "Skipping volume '${name}': legacy v1 reference '${vol.reference}' was not upgraded by the server — use v4 volume syntax or an explicit volume name"
            } else if (vol.use == 'persistent' || vol.name) {
                filtered[name] = new Volume(use: vol.use, name: vol.name)
            } else {
                log.debug "Excluding ephemeral volume '${name}' from task workflows"
            }
        }
        log.info "Filtered volumes: ${filtered.size()} persistent volumes out of ${allVolumes.size()} total volumes"
        return filtered
    }

    /**
     * Keep only the mounts that point at a persistent volume. v4 mounts are
     * path-keyed: the map key is the container path and mount.volume holds the
     * volume name.
     */
    protected static Map<String, WorkflowDefinitionJobMount> filterMounts(
        Map<String, WorkflowDefinitionJobMount> allMounts,
        Map<String, Volume> persistentVolumes
    ) {
        return allMounts.findAll { String path, WorkflowDefinitionJobMount mount ->
            persistentVolumes.containsKey(mount.volume)
        }
    }

}
