package com.ciq.fuzzball

import groovy.transform.CompileStatic
import nextflow.plugin.BasePlugin
import org.pf4j.PluginWrapper

import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.DumperOptions
import com.ciq.fuzzball.api.WorkflowServiceApi

/**
 * Fuzzball (https://ciq.com/products/fuzzball/) plugin entry point
 */
@CompileStatic
class FuzzballPlugin extends BasePlugin {

    FuzzballPlugin(PluginWrapper wrapper) {
        super(wrapper)
    }

}