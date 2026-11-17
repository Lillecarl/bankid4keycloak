package org.keycloak.broker.bankid.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

// BankID adds response fields without notice and says a client must accept them.
@JsonIgnoreProperties(ignoreUnknown = true)
public class StepUp {

    Boolean mrtd;

    public Boolean getMrtd() {
        return mrtd;
    }

    public void setMrtd(Boolean mrtd) {
        this.mrtd = mrtd;
    }
    
}
