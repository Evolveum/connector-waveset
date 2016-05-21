package com.evolveum.polygon.connector.waveset;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;

/**
 * Created by gpalos on 18. 5. 2016.
 */
public class WavesetFilterTranslator extends AbstractFilterTranslator<WavesetFilter> {
    private static final Log LOG = Log.getLog(WavesetFilterTranslator.class);

    @Override
    protected WavesetFilter createEqualsExpression(EqualsFilter filter, boolean not) {
        LOG.ok("createEqualsExpression, filter: {0}, not: {1}", filter, not);

        if (not) {
            return null;            // not supported
        }

        Attribute attr = filter.getAttribute();
        LOG.ok("attr.getName:  {0}, attr.getValue: {1}", attr.getName(), attr.getValue());
        if (Name.NAME.equals(attr.getName())) {
            if (attr.getValue() != null && attr.getValue().get(0) != null) {
                WavesetFilter lf = new WavesetFilter();
                lf.byAccountId = String.valueOf(attr.getValue().get(0));
                return lf;
            }
        } else if (Uid.NAME.equals(attr.getName())) {
            if (attr.getValue() != null && attr.getValue().get(0) != null) {
                WavesetFilter lf = new WavesetFilter();
                lf.byId = String.valueOf(attr.getValue().get(0));
                return lf;
            }
        }

        return null;            // not supported
    }
}
