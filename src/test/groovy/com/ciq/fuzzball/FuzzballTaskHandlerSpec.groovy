// Copyright 2025 CIQ, Inc. All rights reserved.
package com.ciq.fuzzball

import nextflow.processor.TaskRun
import nextflow.processor.TaskConfig
import nextflow.Session
import java.nio.file.Path

import com.ciq.fuzzball.api.WorkflowServiceApi
import com.ciq.fuzzball.model.FuzzballApiV4GetWorkflowStatusResponse as GetWorkflowStatusResponse
import com.ciq.fuzzball.model.FuzzballApiV4WorkflowStatus as WorkflowStatus
import static nextflow.processor.TaskStatus.COMPLETED
import static nextflow.processor.TaskStatus.RUNNING

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
        }
        def handler = new FuzzballTaskHandler(task, executor)
        handler.fuzzballWfService = wfService
        return handler
    }

    def 'killTask swallows exception when stopWorkflow fails'() {
        given:
        def wfService = Mock(WorkflowServiceApi)
        def handler = makeHandler(wfService)
        handler.wfId = 'test-workflow-id'

        when:
        handler.killTask()

        then:
        1 * wfService.stopWorkflow('test-workflow-id') >> { throw new IOException('simulated API failure') }
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

    private FuzzballTaskHandler makeRunningHandler(WorkflowServiceApi wfService) {
        def handler = makeHandler(wfService)
        handler.wfId = 'test-workflow-id'
        handler.status = RUNNING
        return handler
    }

    def 'checkIfCompleted keeps polling while unknown statuses stay within the retry budget'() {
        given:
        def wfService = Mock(WorkflowServiceApi) {
            getWorkflowStatus(_) >> new GetWorkflowStatusResponse(workflowStatus: null)
        }
        def handler = makeRunningHandler(wfService)

        expect: 'the first MAX_UNKNOWN_STATUS_RETRIES unknown statuses are tolerated'
        (1..FuzzballTaskHandler.MAX_UNKNOWN_STATUS_RETRIES).every { !handler.checkIfCompleted() }
        handler.status == RUNNING
    }

    def 'checkIfCompleted fails the task once the unknown status retry budget is exhausted'() {
        given:
        def wfService = Mock(WorkflowServiceApi) {
            getWorkflowStatus(_) >> new GetWorkflowStatusResponse(workflowStatus: null)
        }
        def handler = makeRunningHandler(wfService)
        FuzzballTaskHandler.MAX_UNKNOWN_STATUS_RETRIES.times { handler.checkIfCompleted() }

        when:
        def completed = handler.checkIfCompleted()

        then:
        completed
        handler.status == COMPLETED
        1 * handler.task.setExitStatus(Integer.MAX_VALUE)
    }

    def 'checkIfCompleted resets the unknown status counter on a recognized status'() {
        given:
        def statuses = ([null] * FuzzballTaskHandler.MAX_UNKNOWN_STATUS_RETRIES) +
                [WorkflowStatus.STAGE_STATUS_STARTED] +
                ([null] * FuzzballTaskHandler.MAX_UNKNOWN_STATUS_RETRIES)
        def wfService = Mock(WorkflowServiceApi) {
            getWorkflowStatus(_) >>> statuses.collect { new GetWorkflowStatusResponse(workflowStatus: it) }
        }
        def handler = makeRunningHandler(wfService)

        expect: 'no poll completes the task because the unknown runs never exceed the budget'
        statuses.every { !handler.checkIfCompleted() }
        handler.status == RUNNING
    }

}
