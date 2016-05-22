package com.evolveum.polygon.connector.waveset;

/**
 * Created by gpalos on 18. 5. 2016.
 */
public class WavesetFilter {

    public String byName;

    public String byId;

    @Override
    public String toString() {
        return "WavesetFilter{" +
                "byName='" + byName + '\'' +
                "byId='" + byId + '\'' +
                '}';
    }
}
