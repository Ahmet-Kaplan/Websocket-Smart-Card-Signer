/*
    Websocket Smartcard Signer
    Copyright (C) 2017  Damiano Falcioni (damiano.falcioni@gmail.com)
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. 
 */
package df.sign;

import df.sign.server.pdfSign;
import java.util.List;

import df.sign.datastructure.Data;
import df.sign.pkcs11.SmartCardAccessManagerFactory;
import df.sign.pkcs11.SmartCardAccessManagerFactory.PKCS11AccessMethod;

public class SignFactory {

    public static PKCS11AccessMethod pkcs11AccessMethod = SmartCardAccessManagerFactory.PKCS11AccessMethod.IAIK;

    private static SignEngine signEngine = null;
    private static pdfSign pdfsign = null;

    public static pdfSign getUniquePDFSign() throws Exception {
        if (pdfsign == null) {
            pdfsign = new pdfSign(getUniqueEngine());
        }
        return pdfsign;
    }

    public static SignEngine getUniqueEngine() throws Exception {
        if (signEngine == null) {
            signEngine = new SignEngine(SmartCardAccessManagerFactory.getSmartCardAccessManager(pkcs11AccessMethod), SignUtils.standardDllList);
        }
        return signEngine;
    }

    public static List<Data> performSign(String certId, String Pin, List<Data> dataToSignList) throws Exception {
        return performSign(certId, Pin, dataToSignList, null);
    }

    public static List<Data> performSign(String certId, String Pin, List<Data> dataToSignList, String[] dllList) throws Exception {
        if (dllList != null && dllList.length != 0) {
            SignFactory.getUniqueEngine().dllList = dllList;
        }

        SignFactory.getUniqueEngine().cleanDataToSign().loadDataToSign(dataToSignList);

        pdfsign = SignFactory.getUniquePDFSign();

        pdfsign.sign(certId, Pin);

        List<Data> signedDataList = SignFactory.getUniqueEngine().getSignedData();

        return signedDataList;
    }

}
