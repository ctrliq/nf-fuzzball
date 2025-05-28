/*
 * Copyright 2025, Seqera Labs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ciq.fuzzball

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import nextflow.Session
import nextflow.processor.TaskHandler
import nextflow.processor.TaskProcessor
import nextflow.trace.TraceObserver
import nextflow.trace.TraceRecord

import java.nio.file.Path

/**
 * Implements an observer that allows implementing custom
 * logic on nextflow execution events.
 */
@Slf4j
@CompileStatic
class FuzzballTraceObserver implements TraceObserver {

    @Override
    void onFlowCreate(Session session) {
        println "Pipeline is starting! 🚀"
    }

    @Override
    void onFlowComplete() {
        println "Pipeline complete! 👋"
    }

    @Override
    void onFlowBegin() {}

    @Override
    void onProcessCreate(TaskProcessor process) {
        println "Process created!"
    }

    @Override
    void onProcessTerminate(TaskProcessor process) {}

    @Override
    void onProcessPending(TaskHandler handler, TraceRecord trace) {}

    @Override
    void onProcessSubmit(TaskHandler handler, TraceRecord trace) {
        println "Process submitted!"
    }

    @Override
    void onProcessStart(TaskHandler handler, TraceRecord trace) {
        println "Process started!"
    }

    @Override
    void onProcessComplete(TaskHandler handler, TraceRecord trace) {
        println "Process completed!"
    }

    @Override
    void onProcessCached(TaskHandler handler, TraceRecord trace) {}

    @Override
    boolean enableMetrics() { false }

    @Override
    void onFlowError(TaskHandler handler, TraceRecord trace) {}

    @Override
    void onWorkflowPublish(String name, Object value) {}

    @Override
    void onFilePublish(Path destination) {}

    @Override
    void onFilePublish(Path destination, Path source) {
        onFilePublish(destination)
    }

    @Override
    void onFilePublish(Path destination, Path source, Map annotations) {
        onFilePublish(destination, source)
    }
}