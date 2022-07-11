package it.eng.crypto.data;

import java.util.List;

public class DataSigner {

    private List<AbstractSigner> signersManager;

    public List<AbstractSigner> getSignersManager() {
        return signersManager;
    }

    public void setSignersManager(List<AbstractSigner> signersManager) {
        this.signersManager = signersManager;
    }
}
