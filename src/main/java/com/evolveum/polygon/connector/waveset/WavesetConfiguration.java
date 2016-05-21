/*
 * Copyright (c) 2016 Evolveum
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

package com.evolveum.polygon.connector.waveset;


import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.FrameworkUtil;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

import java.util.*;

import static org.identityconnectors.common.StringUtil.isBlank;

/**
 * @author gpalos
 */
public class WavesetConfiguration extends AbstractConfiguration {

    private static final Log LOG = Log.getLog(WavesetConfiguration.class);

    private String url;

    private String username;

    private GuardedString password;

    private String objectClass = "CustomMidPointUser";

    private Boolean traceSpml = false;

    private String ATTRIBUTES_DELIMITER = ":";
    private String[] attributes;

    // what attribute is what type
    Map<String, Class> attributesClass = new LinkedHashMap<String, Class>();

    private static final Set<Class<?>> SUPPORTED_ATTRIBUTE_TYPES;
    static {
        SUPPORTED_ATTRIBUTE_TYPES = new HashSet<Class<?>>();

        SUPPORTED_ATTRIBUTE_TYPES.addAll(FrameworkUtil.getAllSupportedAttributeTypes());

//        SUPPORTED_ATTRIBUTE_TYPES.add(Date.class);
    }

    List<String> multiValueAttributes = new LinkedList<String>();


    @Override
    public void validate() {
        if (isBlank(url))
            throw new ConfigurationException("url is empty");
        if (isBlank(username))
            throw new ConfigurationException("username is empty");
        if (isBlank(getPlainPassword()))
            throw new ConfigurationException("password is empty");

        parseAttributes();
    }

    protected void parseAttributes() {
        if (this.attributes == null || this.attributes.length == 0) {
            return;
        }

        if (!attributesClass.isEmpty()) {
            LOG.ok("parsing attributes was mades in the past, ignoring: {0}", this.attributesClass);
            return;
        }

        LOG.ok("parsing attributes: {0}", Arrays.toString(this.attributes));
        for (int i = 0; i < attributes.length; i++) {
            String[] attribute = attributes[i].split(ATTRIBUTES_DELIMITER);
            if (attribute == null || attribute.length > 3) {
                throw new ConfigurationException("attribute is not parsable '" + attributes[i] + "', example: 'roles:java.util.String:MULTIVALUED'");
            }

            if (StringUtil.isEmpty(attribute[0])) {
                throw new ConfigurationException("attribute name is empty for " + attributes[i]);
            }


            Class<?> type = String.class;
            if (attribute.length >= 2) {
                if (StringUtil.isEmpty(attribute[1])) {
                    throw new ConfigurationException("attribute type is empty for " + attributes[i]);
                }
                else {
                    try {
                        type = Class.forName(attribute[1]);
                        if (!SUPPORTED_ATTRIBUTE_TYPES.contains(type)) {
                            throw new ConfigurationException("attribute type '" + type.getName() + "' is not supported for " + attributes[i]);
                        }
                    } catch (ClassNotFoundException e) {
                        throw new ConfigurationException("attribute type '" + attribute[0] + "' is not found for " + attributes[i] + ", " + e, e);
                    }
                }
            }
            attributesClass.put(attribute[0], type);

            if (attribute.length >= 3) {
                if (StringUtil.isEmpty(attribute[2])) {
                    throw new ConfigurationException("attribute flag is empty for " + attributes[i]);
                }
                else {
                    multiValueAttributes.add(attribute[0]);
                }
            }

        }

        LOG.ok("parsed attribute: {0}", this.attributesClass);
    }


    @ConfigurationProperty(displayMessageKey = "waveset.config.url",
            helpMessageKey = "sunidm.config.url.help")
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @ConfigurationProperty(displayMessageKey = "waveset.config.username",
            helpMessageKey = "sunidm.config.username.help")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @ConfigurationProperty(displayMessageKey = "waveset.config.password",
            helpMessageKey = "sunidm.config.password.help")
    public GuardedString getPassword() {
        return password;
    }

    public void setPassword(GuardedString password) {
        this.password = password;
    }

    protected String getPlainPassword() {
        final StringBuilder sb = new StringBuilder();
        if (password != null) {
            password.access(new GuardedString.Accessor() {
                @Override
                public void access(char[] chars) {
                    sb.append(new String(chars));
                }
            });
        } else {
            return null;
        }
        return sb.toString();
    }

    @ConfigurationProperty(displayMessageKey = "waveset.config.traceSpml",
            helpMessageKey = "sunidm.config.traceSpml.help")
    public Boolean getTraceSpml() {
        return traceSpml;
    }

    public void setTraceSpml(Boolean traceSpml) {
        this.traceSpml = traceSpml;
    }

    @ConfigurationProperty(displayMessageKey = "waveset.config.objectClass",
            helpMessageKey = "sunidm.config.objectClass.help")
    public String getObjectClass() {
        return objectClass;
    }

    public void setObjectClass(String objectClass) {
        this.objectClass = objectClass;
    }

    @ConfigurationProperty(displayMessageKey = "waveset.config.attributes",
            helpMessageKey = "sunidm.config.attributes.help")
    public String[] getAttributes() {
        return attributes;
    }

    public void setAttributes(String[] attributes) {
        this.attributes = attributes;
    }

    public Map<String, Class> getAttributesClass() {
        return attributesClass;
    }

    public Set<String> getAttributeNames() {
        if (attributesClass.isEmpty()) {
            return new HashSet<String>();
        }

        return attributesClass.keySet();
    }

    public boolean containsAttributeName(String attrName) {
        if (attributesClass.isEmpty()) {
            return false;
        }

        return attributesClass.keySet().contains(attrName);
    }


    public Class getAttributeType(String key) {
        if (!attributesClass.containsKey(key)) {
            return null;
        }

        return attributesClass.get(key);
    }

    public boolean isMultiValueAttribute(String attributeName){
        if (multiValueAttributes.contains(attributeName)) {
            return true;
        }

        return false;
    }

}