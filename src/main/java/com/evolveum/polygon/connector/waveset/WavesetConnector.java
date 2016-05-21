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
import org.identityconnectors.framework.common.exceptions.*;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.*;
import org.openspml.client.LighthouseClient;
import org.openspml.message.*;
import org.openspml.message.Attribute;
import org.openspml.message.SearchResult;
import org.openspml.util.SpmlException;

import java.util.*;

/**
 * @author gpalos
 */
@ConnectorClass(displayNameKey = "sunidm.connector.display", configurationClass = WavesetConfiguration.class)
public class WavesetConnector implements Connector, TestOp, SchemaOp, SearchOp<WavesetFilter>, CreateOp, DeleteOp, UpdateOp {

    private static final Log LOG = Log.getLog(WavesetConnector.class);

    private WavesetConfiguration configuration;

    private LighthouseClient client;

    private static final String ATTR_ID = "id"; //__UID__
    private static final String ATTR_ACCOUNT_ID = "accountId"; // __NAME__
    private static final String ATTR_DISABLED = "disabled"; //Administrative Status
    private static final String ATTR_LOCKED = "locked"; //Lock-out Status
    private static final String ATTR_PASSWORD = "password"; //password
//    private static final String ATTR_lOCK_EXPIRY = "lockExpiry"; //Lock-out Expiration


    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        LOG.ok("connector init");
        this.configuration = (WavesetConfiguration)configuration;
        this.configuration.parseAttributes();
        try {
            this.client = new LighthouseClient();
            this.client.setUrl(this.configuration.getUrl());
            this.client.setUser(this.configuration.getUsername());
            this.client.setPassword(this.configuration.getPlainPassword());
            if (this.configuration.getTraceSpml() != null && this.configuration.getTraceSpml()) {
                this.client.setTrace(true);
            }
            this.client.login();
        } catch (Exception e) {
            LOG.error(e, "Connection failed to: " + this.configuration.getUrl());
            throw new ConnectorIOException(e.getMessage(), e);
        }
    }

    @Override
    public void dispose() {
        configuration = null;
        if (this.client != null) {
            try {
                this.client.logout();
                this.client = null;
            } catch (SpmlException e) {
                LOG.warn(e, "Error when dispose: " + e);
            }
        }
    }

    @Override
    public void test() {
        try {
            // find account configurator
            SearchRequest searchRequest = new SearchRequest();
            Identifier id = new Identifier();
            id.setId("configurator");
            searchRequest.setIdentifier(id);
            this.client.searchRequest(searchRequest);
        } catch (SpmlException e) {
            throw new ConnectorIOException(e.getMessage(), e);
        }
    }

    @Override
    public Schema schema() {
        SchemaBuilder builder = new SchemaBuilder(WavesetConnector.class);

        builder.defineObjectClass(schemaAccount());
//        builder.defineObjectClass(schemaOrganization());

        return builder.build();
    }

    private ObjectClassInfo schemaAccount() {
        ObjectClassInfoBuilder objClassBuilder = new ObjectClassInfoBuilder();

        AttributeInfoBuilder uidAib = new AttributeInfoBuilder(Uid.NAME);
        uidAib.setRequired(true);
        objClassBuilder.addAttributeInfo(uidAib.build());

        AttributeInfoBuilder nameAib = new AttributeInfoBuilder(Name.NAME);
        nameAib.setRequired(true);
        objClassBuilder.addAttributeInfo(nameAib.build());

        for (String att : configuration.getAttributeNames()) {
            // read only and other flags? - not important jet
            Class type = configuration.getAttributeType(att);
            AttributeInfoBuilder aib = new AttributeInfoBuilder(att, type);
            if (configuration.isMultiValueAttribute(att)) {
                aib.setMultiValued(true);
            }
            objClassBuilder.addAttributeInfo(aib.build());
        }

        objClassBuilder.addAttributeInfo(OperationalAttributeInfos.ENABLE); //Administrative Status
        // only read only - user unlocked automatically when update/delete operation occured
        AttributeInfoBuilder locked = new AttributeInfoBuilder(OperationalAttributes.LOCK_OUT_NAME, Boolean.class);
        locked.setReadable(true);
        locked.setCreateable(false);
        locked.setUpdateable(false);
        objClassBuilder.addAttributeInfo(OperationalAttributeInfos.LOCK_OUT); //Lock-out Status
//        objClassBuilder.addAttributeInfo(OperationalAttributeInfos.); //Lock-out Expiration???

        objClassBuilder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);

        return objClassBuilder.build();
    }

    @Override
    public FilterTranslator<WavesetFilter> createFilterTranslator(ObjectClass objectClass, OperationOptions operationOptions) {
        return new WavesetFilterTranslator();
    }

    @Override
    public void executeQuery(ObjectClass objectClass, WavesetFilter query, ResultsHandler handler, OperationOptions operationOptions) {
        if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
            try {
                LOG.ok("executeQuery: {0}, options: {1}", query, operationOptions);
                // find by accountId
                if (query != null && query.byAccountId != null) {

                    List results = findAccount(query.byAccountId, true);

                    if (results != null && results.size() > 0) {
                        for (Object result : results) {
                            ConnectorObject connectorObject = convertAccountToConnectorObject((org.openspml.message.SearchResult) result);
                            handler.handle(connectorObject);
                        }
                    }

                }else if (query != null && query.byId != null) {

                    List results = findAccount(query.byId, false);

                    if(results != null && results.size() > 0) {
                        for (Object result : results) {
                            ConnectorObject connectorObject = convertAccountToConnectorObject((org.openspml.message.SearchResult) result);
                            handler.handle(connectorObject);
                        }
                    }

                } else {
                    SearchRequest req = new SearchRequest();
                    addRequestAttributes(req);

                    req.addCondition("objectclass", configuration.getObjectClass());
                    SearchResponse response = this.client.searchRequest(req);
                    client.throwErrors(response);
                    List results = response.getResults();
                    int count = 0;
                    if(results != null && results.size() > 0) {
                        for (Object result : results) {
                            if (++count % 10 == 0) {
                                LOG.ok("executeQuery: processing {0}. of {1} accounts", count, results.size());
                            }
                            ConnectorObject connectorObject = convertAccountToConnectorObject((org.openspml.message.SearchResult) result);
                            boolean finish = !handler.handle(connectorObject);
                            if (finish)
                                break;
                        }
                    }
                }

            } catch (SpmlException e) {
                throw new ConnectorIOException(e.getMessage(), e);
            }
        } else {
            throw new UnsupportedOperationException("Unsupported object class " + objectClass);
        }
    }

    private List findAccount(String id, boolean byAccountId) throws SpmlException {
        // objectclass=CustomMidPointUser and accountId=test01
        SearchRequest req = new SearchRequest();
        addRequestAttributes(req);

        FilterTerm ftoc = new FilterTerm();
        ftoc.setOperation(FilterTerm.OP_EQUAL);
        ftoc.setName("objectclass");
        ftoc.setValue(configuration.getObjectClass());

        FilterTerm ftid = new FilterTerm();
        ftid.setOperation(FilterTerm.OP_EQUAL);
        String filter = byAccountId ? ATTR_ACCOUNT_ID : "identifier";
        ftid.setName(filter);
        ftid.setValue(id);

        FilterTerm and = new FilterTerm();
        and.setOperation(FilterTerm.OP_AND);
        and.addOperand(ftoc);
        and.addOperand(ftid);

        req.addFilterTerm(and);

        SearchResponse response = this.client.searchRequest(req);
        client.throwErrors(response);

        return response.getResults();
    }

    private String findAccountId(Uid uid) throws SpmlException {
        try {
            List results = findAccount(uid.getUidValue(), false);
            if(results == null || results.size() == 0) {
                throw new UnknownUidException("Account " + uid + " not exists");
            }
            else if (results.size() == 1){
                SearchResult res = (SearchResult) results.get(0);
//                return res.getIdentifierString();
                return getAttribute(res, ATTR_ACCOUNT_ID, String.class);
            }
            else {
                throw new ConnectorIOException("too many accouts on target resource with UID "+uid.getUidValue()+", expected 1, get "+results.size()+", results: "+results);
            }
        } catch (SpmlException e) {
            LOG.warn("Exception when finding existing account: "+uid, e);
            throw e;
        }

    }

    private void addRequestAttributes(SearchRequest req) {
        req.addAttribute(ATTR_ID);
        req.addAttribute(ATTR_ACCOUNT_ID);
        req.addAttribute(ATTR_DISABLED);
        req.addAttribute(ATTR_LOCKED);

        for (String attribute : configuration.getAttributeNames()) {
            req.addAttribute(attribute);
        }
    }

    private ConnectorObject convertAccountToConnectorObject(org.openspml.message.SearchResult result) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setUid(getAttribute(result, ATTR_ID, String.class));
        builder.setName(getAttribute(result, ATTR_ACCOUNT_ID, String.class));

        for (String attribute : configuration.getAttributeNames()){
            if (configuration.isMultiValueAttribute(attribute)) {
                String[] multiValues = getMultiValues(result, attribute);
                if (multiValues != null) {
                    builder.addAttribute(AttributeBuilder.build(attribute, multiValues));
                }
            }
            else {
                addAttr(builder, attribute, getAttribute(result, attribute, configuration.getAttributeType(attribute)));
            }
        }

        String disabled = getAttribute(result, ATTR_DISABLED, String.class);
        addAttr(builder, OperationalAttributes.ENABLE_NAME, !parseTrue(disabled));

        String locked = getAttribute(result, ATTR_LOCKED, String.class);
        addAttr(builder, OperationalAttributes.LOCK_OUT_NAME, parseTrue(locked));

        ConnectorObject connectorObject = builder.build();
        LOG.ok("convertAccountToConnectorObject, account: {0}, disabled: {1}, locked: {2}, \n\tconnectorObject: {3}",
                result.getIdentifierString(), disabled, locked, connectorObject);
        return connectorObject;

    }

    // in SunIDM "true" is enabled, null is disabled
    private Boolean parseTrue(String val)
    {
        if (StringUtil.isBlank(val)) {
            return false;
        }
        if (val.equalsIgnoreCase("true")) {
            return true;
        }

        return false;
    }

    private String[] getMultiValues(SearchResult result, String attributeName) {
        Attribute attribute = result.getAttribute(attributeName);
        if (attribute == null) {
            return null;
        }

        if (attribute.getValue() == null) {
            return null;
        }

        if (attribute.getValue() instanceof String) {
            return new String[]{(String)attribute.getValue()};
        }
        else if (attribute.getValue() instanceof ArrayList) {
            ArrayList values = (ArrayList)attribute.getValue();
            List<String> val = new LinkedList<String>();
            for (Object v : values) {
                if (v instanceof String) {
                    val.add((String) v);
                }
                else {
                    throw new InvalidAttributeValueException("value: "+v+" for attribute "+attributeName+" with type: "+v.getClass()+" is not supported");
                }
            }
            return val.toArray(new String[0]);
        }
        else {
            throw new InvalidAttributeValueException("value: "+attribute.getValue()+" for attribute "+attributeName+" is not supported");
        }
    }


    private  <T> T getAttribute(SearchResult result, String attrName, Class<T> type) {
        Attribute attribute = result.getAttribute(attrName);
        if (attribute == null) {
            return null;
        }

        return (T)attribute.getValue();
    }

    private <T> void addAttr(ConnectorObjectBuilder builder, String attrName, T attrVal) {
        if (attrVal != null) {
            builder.addAttribute(attrName, attrVal);
        }
    }

    private <T> T getAttr(Set<org.identityconnectors.framework.common.objects.Attribute> attributes, String attrName, Class<T> type, T defaultVal, boolean notNull) throws InvalidAttributeValueException {
        T ret = getAttr(attributes, attrName, type, defaultVal);
        if (notNull && ret == null)
            return defaultVal;
        return ret;
    }

    private <T> T getAttr(Set<org.identityconnectors.framework.common.objects.Attribute> attributes, String attrName, Class<T> type) throws InvalidAttributeValueException {
        return getAttr(attributes, attrName, type, null);
    }


    @SuppressWarnings("unchecked")
    public <T> T getAttr(Set<org.identityconnectors.framework.common.objects.Attribute> attributes, String attrName, Class<T> type, T defaultVal) throws InvalidAttributeValueException {
        for (org.identityconnectors.framework.common.objects.Attribute attr : attributes) {
            if (attrName.equals(attr.getName())) {
                List<Object> vals = attr.getValue();
                if (vals == null || vals.isEmpty()) {
                    // set empty value
                    return null;
                }
                if (vals.size() == 1) {
                    Object val = vals.get(0);
                    if (val == null) {
                        // set empty value
                        return null;
                    }
                    if (type.isAssignableFrom(val.getClass())) {
                        return (T) val;
                    }
                    throw new InvalidAttributeValueException("Unsupported type " + val.getClass() + " for attribute " + attrName);
                }
                throw new InvalidAttributeValueException("More than one value for attribute " + attrName);
            }
        }
        // set default value when attrName not in changed attributes
        return defaultVal;
    }

    @Override
    public Uid create(ObjectClass objectClass, Set<org.identityconnectors.framework.common.objects.Attribute> attributes, OperationOptions operationOptions) {
        if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {    // __ACCOUNT__
            return createAccount(attributes);
        } else {
            throw new UnsupportedOperationException("Unsupported object class " + objectClass);
        }
    }

    private Uid createAccount(Set<org.identityconnectors.framework.common.objects.Attribute> attributes) {
        LOG.ok("createAccount attributes: {0}", attributes);
        String id = getAttr(attributes, Name.NAME, String.class, null);
        if (StringUtil.isBlank(id)) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + Name.NAME);
        }

        Map spmlAttributes = prepareSpmlAttributes(attributes);

        final List<String> passwordList = new ArrayList<String>(1);
        GuardedString guardedPassword = getAttr(attributes, OperationalAttributeInfos.PASSWORD.getName(), GuardedString.class);
        if (guardedPassword != null) {
            guardedPassword.access(new GuardedString.Accessor() {
                @Override
                public void access(char[] chars) {
                    passwordList.add(new String(chars));
                }
            });
        }
        String password = null;
        if (!passwordList.isEmpty()) {
            password = passwordList.get(0);
        }

        // TODO: really?
        if (StringUtil.isBlank(password)) {
            throw new InvalidAttributeValueException("Missing mandatory attribute " + OperationalAttributes.PASSWORD_NAME);
        }
        else {
            spmlAttributes.put(ATTR_PASSWORD, password);
        }

        try {
            List results = findAccount(id, true);
            if(results != null && results.size() > 0) {
                throw new AlreadyExistsException("Account with id '" + id + "' already exists: " + results);
            }
        } catch (SpmlException e) {
            LOG.warn("Exception when finding existing account: "+id, e);
        }

        try {
            AddRequest req = new AddRequest();
            req.setIdentifier(id);
            req.setObjectClass(configuration.getObjectClass());
            req.setAttributes(spmlAttributes);
            SpmlResponse response = client.request(req);
            client.throwErrors(response);

            // read uid
            String uid = null;
            List results = findAccount(id, true);
            if(results != null && results.size() == 1) {
                uid = getAttribute((SearchResult)results.get(0), ATTR_ID, String.class);
            }
            else {
                throw new ConnectorIOException("can't find UID for new account "+id+", results: "+results);
            }

            // enable/disable & unlock
            handleDisabledLocked(attributes, id);

            LOG.ok("New account created, id: {0}, Uid: {1}", id, uid);

            return new Uid(uid);
        } catch (SpmlException e) {
            throw new ConnectorIOException(e.getMessage(), e);
        }
    }

    private Map prepareSpmlAttributes(Set<org.identityconnectors.framework.common.objects.Attribute> attributes) {
        Map ret = new HashMap();
        for (org.identityconnectors.framework.common.objects.Attribute attribute : attributes) {
            String name = attribute.getName();
            if (ATTR_ACCOUNT_ID.equals(name)) {
                throw new PermissionDeniedException("Rename account operation is not supported yet");
            }

            // handled elsewhere
            if (name.equals(ATTR_DISABLED) || name.equals(ATTR_LOCKED) || name.equals(OperationalAttributes.PASSWORD_NAME)) {
                continue;
            }

            // ignore & log as warning other not supported attributes
            if (!configuration.containsAttributeName(name)) {
                LOG.warn("attribute {0} is not in configured attribute list: {1}, ignoring ", attribute, configuration.getAttributeNames());
                continue;
            }

            Class type = configuration.getAttributeType(name);
            Object value = null;
            if (configuration.isMultiValueAttribute(name)) {
                value = getMultiValAttr(attributes, name, type, null);
            }
            else {
                value = getAttr(attributes, name, type);
            }

            ret.put(name, value);
        }

        return ret;
    }

    private List<String> getMultiValAttr(Set<org.identityconnectors.framework.common.objects.Attribute> attributes, String attrName, Class type, List<String> defaultVal) {
        if (!type.getName().contains("String")) {
            throw new InvalidAttributeValueException("not supported multi value type: "+type+" for attribute: "+attrName);
        }
        for (org.identityconnectors.framework.common.objects.Attribute attr : attributes) {
            if (attrName.equals(attr.getName())) {
                List<Object> vals = attr.getValue();
                if (vals == null || vals.isEmpty()) {
                    // set empty value
                    return new ArrayList<String>();
                }
                List<String> ret = new ArrayList<String>();
                for (int i = 0; i < vals.size(); i++) {
                    Object valAsObject = vals.get(i);
                    if (valAsObject == null)
                        throw new InvalidAttributeValueException("Value " + null + " must be not null for attribute " + attrName);

                    String val = (String) valAsObject;
                    ret.add(val);
                }
                return ret;
            }
        }
        // set default value when attrName not in changed attributes
        return defaultVal;
    }

    private void handleDisabledLocked(Set<org.identityconnectors.framework.common.objects.Attribute> attributes, String accountId) throws SpmlException {
        Boolean enable = getAttr(attributes, OperationalAttributes.ENABLE_NAME, Boolean.class);
        Boolean locked = getAttr(attributes, OperationalAttributes.LOCK_OUT_NAME, Boolean.class);

        if (enable != null) {
            ExtendedRequest req = new ExtendedRequest();
            String operation = enable ? "enableUser" : "disableUser";
            req.setOperationIdentifier(operation);

            req.setAttribute(ATTR_ACCOUNT_ID, accountId);

            SpmlResponse response = client.request(req);
            client.throwErrors(response);
            LOG.info("called operation "+operation+" for "+accountId);
        }

        if (locked != null && !locked) {
            unlockAccount(accountId);
        }
    }

    private void unlockAccount(String accountId) throws SpmlException {
        ExtendedRequest req = new ExtendedRequest();
        String operation = "unlockUser";
        req.setOperationIdentifier(operation);

        req.setAttribute(ATTR_ACCOUNT_ID, accountId);

        SpmlResponse response = client.request(req);
        client.throwErrors(response);
        LOG.info("called operation "+operation+" for "+accountId);
    }

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions operationOptions) {
        if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
            String accountId = null;
            try {
                LOG.ok("delete account, Uid: {0}", uid);

                // check if exists & read his accountId - NAME
                accountId = findAccountId(uid);

                // delete it
                deleteAccount(accountId);

            } catch (SpmlException e) {
                if (e.toString().contains("Invalid type")) {
                    LOG.error(e, "Exception when deleting account with id "+accountId+", UID "+uid.getUidValue()+", "+e);
                    throw new UnknownUidException("Account id "+accountId+", UID "+uid.getUidValue()+", not exists", e);
                } else if (e.toString().contains("already locked by")) {
                    // account is locked by GUI, unlock it and try delete again
                    try {
                        LOG.warn(e, "Account is locked, trying to unlock and delete again with id " + accountId + ", UID " + uid.getUidValue() + ", " + e);
                        unlockAccount(accountId);
                        deleteAccount(accountId);
                    } catch (SpmlException e1) {
                        LOG.error(e, "Delete again failed with id " + accountId + ", UID " + uid.getUidValue() + ", " + e);
                        throw new ConnectorIOException(e1.getMessage(), e1);
                    }
                }
                else {
                    throw new ConnectorIOException(e.getMessage(), e);
                }
            }
        } else {
            throw new UnsupportedOperationException("Unsupported object class " + objectClass);
        }

    }

    private void deleteAccount(String accountId) throws SpmlException {
        DeleteRequest req = new DeleteRequest();
        req.setIdentifier(accountId);
        SpmlResponse response = client.request(req);
        client.throwErrors(response);
    }

    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<org.identityconnectors.framework.common.objects.Attribute> attributes, OperationOptions operationOptions) {
        if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
            return updateAccount(uid, attributes);
        } else {
            throw new UnsupportedOperationException("Unsupported object class " + objectClass);
        }

    }


    private Uid updateAccount(Uid uid, Set<org.identityconnectors.framework.common.objects.Attribute> attributes) {
        LOG.ok("updateAccount, Uid: {0}, attributes: {1}", uid, attributes);
        if (attributes == null || attributes.isEmpty()) {
            LOG.ok("update ignored, nothing changed");
            return uid;
        }

        String accountId = null;
        try {

            accountId = findAccountId(uid);

            updateAccount(accountId, attributes);

        } catch (SpmlException e) {
            if (e.toString().contains("Invalid type")) {
                LOG.error(e, "Exception when updatin account with id "+accountId+", UID "+uid.getUidValue()+", "+e);
                throw new UnknownUidException("Account id "+accountId+", UID "+uid.getUidValue()+", not exists", e);
            } else if (e.toString().contains("already locked by")) {
                // account is locked by GUI, unlock it and try update again
                try {
                    LOG.warn(e, "Account is locked, trying to unlock and update again with id " + accountId + ", UID " + uid.getUidValue() + ", " + e);
                    unlockAccount(accountId);
                    updateAccount(accountId, attributes);
                } catch (SpmlException e1) {
                    LOG.error(e, "Update again failed with id " + accountId + ", UID " + uid.getUidValue() + ", " + e);
                    throw new ConnectorIOException(e1.getMessage(), e1);
                }
            }
        }

        return uid;
    }

    private void updateAccount(String accountId, Set<org.identityconnectors.framework.common.objects.Attribute> attributes) throws SpmlException {
        Map modifications = prepareSpmlAttributes(attributes);

        // update account
        if (modifications == null || modifications.isEmpty()) {
            // don't need update
        }
        else {
            LOG.info("accountId: {0}, modifications: {1}", accountId, modifications);
            ModifyRequest req = new ModifyRequest();
            req.setIdentifier(accountId);
            req.setModifications(modifications);
            SpmlResponse response = client.request(req);
            client.throwErrors(response);
        }

        // update password if needed
        final List<String> passwordList = new ArrayList<String>(1);
        GuardedString guardedPassword = getAttr(attributes, OperationalAttributeInfos.PASSWORD.getName(), GuardedString.class);
        if (guardedPassword != null) {
            guardedPassword.access(new GuardedString.Accessor() {
                @Override
                public void access(char[] chars) {
                    passwordList.add(new String(chars));
                }
            });
        }
        String password = null;
        if (!passwordList.isEmpty()) {
            password = passwordList.get(0);

            LOG.info("changing password....");
            ExtendedRequest changePassReq = new ExtendedRequest();
            changePassReq.setOperationIdentifier("changeUserPassword");
            changePassReq.setAttribute("accountId", accountId);
            changePassReq.setAttribute(ATTR_PASSWORD, password);
            SpmlResponse changePassResp = client.request(changePassReq);
            client.throwErrors(changePassResp);
        }

        // enable/disable & unlock
        handleDisabledLocked(attributes, accountId);
    }

}
