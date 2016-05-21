package com.evolveum.polygon.connector.waveset;

/**
 * Created by gpalos on 18. 5. 2016.
 */
public class WavesetFilter {

    public String byAccountId;

    public String byId;

    @Override
    public String toString() {
        return "WavesetFilter{" +
                "byAccountId='" + byAccountId + '\'' +
                "byId='" + byId + '\'' +
                '}';
    }
}
