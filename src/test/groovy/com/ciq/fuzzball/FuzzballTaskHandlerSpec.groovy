// Copyright 2025 CIQ, Inc. All rights reserved.
package com.ciq.fuzzball

import nextflow.processor.TaskRun
import nextflow.processor.TaskConfig
import nextflow.Session
import java.nio.file.Path

import com.ciq.fuzzball.api.WorkflowServiceApi

import spock.lang.Specification

class FuzzballTaskHandlerSpec extends Specification {

    private FuzzballTaskHandler makeHandler(WorkflowServiceApi wfService) {
        def taskWorkDir = Mock(Path) { resolve(_) >> Mock(Path) }
        def task = Mock(TaskRun) {
            workDir >> taskWorkDir
            config >> Mock(TaskConfig) { getTime() >> null }
        }
        def executor = Mock(FuzzballExecutor) {
            session >> Mock(Session)
            fuzzballWfService >> wfService
        }
        return new FuzzballTaskHandler(task, executor)
    }

    def 'killTask swallows exception when stopWorkflow fails'() {
        given:
        def wfService = Mock(WorkflowServiceApi) {
            stopWorkflow(_) >> { throw new IOException('simulated API failure') }
        }
        def handler = makeHandler(wfService)
        handler.wfId = 'test-workflow-id'

        when:
        handler.killTask()

        then:
        noExceptionThrown()
    }

    def 'killTask is a no-op when wfId is null'() {
        given:
        def wfService = Mock(WorkflowServiceApi)
        def handler = makeHandler(wfService)
        // wfId intentionally left null

        when:
        handler.killTask()

        then:
        0 * wfService.stopWorkflow(_)
    }

}
