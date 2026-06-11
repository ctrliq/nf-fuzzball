// Copyright 2026 CIQ, Inc. All rights reserved.
package com.ciq.fuzzball

import spock.lang.Specification

import com.ciq.fuzzball.model.FuzzballApiV4WorkflowDefinitionVolume as Volume
import com.ciq.fuzzball.model.FuzzballApiV4WorkflowDefinitionJobMount as Mount

class FuzzballExecutorSpec extends Specification {

    def 'filterPersistentVolumes keeps named and persistent-use volumes'() {
        given:
        Map<String, Volume> all = [
            'named'    : new Volume(name: 'mydata'),                     // persistent: explicit name
            'pers'     : new Volume(use: 'persistent', name: 'team'),    // persistent
            'provNamed': new Volume(use: 'nfs-prod', name: 'shared'),    // persistent on a provisioner
            'empty'    : new Volume(),                                   // ephemeral: empty block
            'eph'      : new Volume(use: 'ephemeral'),                   // ephemeral
            'provEph'  : new Volume(use: 'nfs-prod', size: '10GB'),      // ephemeral on a provisioner
        ]

        when:
        Map<String, Volume> result = FuzzballExecutor.filterPersistentVolumes(all)

        then:
        result.keySet() == ['named', 'pers', 'provNamed'] as Set
    }

    def 'filterPersistentVolumes copies only use and name'() {
        given:
        Map<String, Volume> all = ['data': new Volume(use: 'nfs-prod', name: 'mydata', size: '10GB')]

        when:
        Volume copied = FuzzballExecutor.filterPersistentVolumes(all)['data']

        then:
        copied.use == 'nfs-prod'
        copied.name == 'mydata'
        copied.size == null
        copied.ingress == []
        copied.egress == []
    }

    def 'filterPersistentVolumes skips volumes with unresolved legacy references'() {
        expect:
        FuzzballExecutor.filterPersistentVolumes(
            ['legacy': new Volume(reference: 'volume://user/persistent')]
        ).isEmpty()
    }

    def 'filterMounts keeps only path-keyed mounts of persistent volumes'() {
        given:
        Map<String, Mount> allMounts = [
            '/data'   : new Mount(volume: 'data'),
            '/scratch': new Mount(volume: 'scratch'),
        ]
        Map<String, Volume> persistent = ['data': new Volume(name: 'mydata')]

        when:
        Map<String, Mount> result = FuzzballExecutor.filterMounts(allMounts, persistent)

        then:
        result.keySet() == ['/data'] as Set
        result['/data'].volume == 'data'
    }
}
