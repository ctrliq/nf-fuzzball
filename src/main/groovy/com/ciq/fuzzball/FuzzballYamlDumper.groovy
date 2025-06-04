package com.ciq.fuzzball

import groovy.transform.CompileStatic

import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.representer.Representer
import org.yaml.snakeyaml.nodes.NodeTuple
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.Tag
import org.yaml.snakeyaml.introspector.Property

/** Custom YAML dumper for Fuzzball that skips null and empty values.
 * This is used to generate YAML files without unnecessary clutter.
 * It extends the standard Yaml class from SnakeYAML with a custom representer.
 */
@CompileStatic
class FuzzballYamlDumper extends Yaml {

    FuzzballYamlDumper() {
        super(createRepresenter(), createOptions())
    }

    private static SkipNullRepresenter createRepresenter() {
        return new SkipNullRepresenter(createOptions())
    }

    private static DumperOptions createOptions() {
        DumperOptions options = new DumperOptions()
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK)
        options.setPrettyFlow(true)
        return options
    }

}

/** Custom represetner to remote empty/null stuff from the output */
@CompileStatic
class SkipNullRepresenter extends Representer {

    SkipNullRepresenter(DumperOptions options) {
        super(options)
    }

    @Override
    protected NodeTuple representJavaBeanProperty(Object javaBean, Property property, Object propertyValue, Tag customTag) {
        if (propertyValue == null) {
            return null
        }
        if (propertyValue instanceof Collection && propertyValue.isEmpty()) {
            return null
        }
        if (propertyValue instanceof Map && propertyValue.isEmpty()) {
            return null
        }
        if (propertyValue instanceof CharSequence && propertyValue.toString().isEmpty()) {
            return null
        }
        return super.representJavaBeanProperty(javaBean, property, propertyValue, customTag)
    }

    @Override
    protected Node representScalar(Tag tag, String value, DumperOptions.ScalarStyle style) {
        // Quote any potentially unsafe strings
        if (value =~ /.*[:#,\[\]\{\}\&\*\!\|\>\<\=\%\@`\'\"\n\r\t].*|^[-?]|^\s|\s$/) {
            return super.representScalar(tag, value, DumperOptions.ScalarStyle.DOUBLE_QUOTED)
        }
        return super.representScalar(tag, value, style)
    }
}
