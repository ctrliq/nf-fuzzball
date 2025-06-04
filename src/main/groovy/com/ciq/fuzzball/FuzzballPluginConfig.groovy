package com.ciq.fuzzball

import nextflow.config.schema.ConfigOption
import nextflow.config.schema.ConfigScope
import nextflow.config.schema.ScopeName
import nextflow.script.dsl.Description

import com.ciq.fuzzball.model.Volume

@ScopeName('fuzzball')
@Description('''
    The `fuzzball` scope allows you to configure the `nf-fuzzball` plugin.
    This is not the same as the Fuzzball API configuration.
''')
class FuzzballPluginConfig implements ConfigScope {

    FuzzballPluginConfig(Map opts) {
        this.cfg = opts.cfg ?: System.getProperty('user.home') + '/.config/fuzzball/config.yaml'
        this.volues = opts.volumes ?: [:]
    }

    // NOTE: configFile and configPath seem to be reserved keywords. This caused me some headaches.
    @ConfigOption
    @Description('Fuzzball configuration file path. Defaults to ~/.config/fuzzball/config.yaml')
    String cfgFile

    @ConfigOption
    @Description('Fuzzball volumes map')
    Map<String, Volume> volumes = [:]
}
