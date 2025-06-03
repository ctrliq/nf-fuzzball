import nextflow.config.schema.ConfigOption
import nextflow.config.schema.ConfigScope
import nextflow.config.schema.ScopeName
import nextflow.script.dsl.Description

@ScopeName('fuzzball')
@Description('''
    The `fuzzball` scope allows you to configure the `nf-fuzzball` plugin.
    This is not the same as the Fuzzball API configuration.
''')
class FuzzballConfig implements ConfigScope {

    FuzzballConfig(Map opts) {
        this.configSecret = opts.configSecret
        this.configFile = opt.configFile ?: System.getProperty('user.home') + '/.config/fuzzball/config.yaml'
    }

    @ConfigOption
    @Description('Fuzzball secret used to store fuzzball API configuration information if running the nextflow controller as a fuzzball job/service')
    String configSecret

    @ConfigOption
    @Description('Fuzzball configuration file path. If configSecret is set, this will be ignored. Defaults to ~/.config/fuzzball/config.yaml')
    String configFile
}
