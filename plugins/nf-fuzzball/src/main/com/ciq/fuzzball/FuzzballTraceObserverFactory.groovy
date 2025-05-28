package com.ciq.fuzzball

import groovy.transform.CompileStatic
import nextflow.Session
import nextflow.trace.TraceObserver
import nextflow.trace.TraceObserverFactory

/**
 * Implements a factory object required to create
 * the {@link FuzzballObserver} instance.
 */
@CompileStatic
class FuzzballTraceObserverFactory implements TraceObserverFactory {

    @Override
    Collection<TraceObserver> create(Session session) {
        return List.<TraceObserver>of(new FuzzballTraceObserver())
    }

}
