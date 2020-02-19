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
package df.sign.pkcs11;

import df.sign.pkcs11.impl.tubitak.SmartCardAccessTubitakImpl;

public class SmartCardAccessManagerFactory {

    public static enum PKCS11AccessMethod {
        JNA,
        TUBITAK,
        TEMP
    };
    private static SmartCardAccessTubitakImpl smartCardAccessManager_tubitak = null;

    public static SmartCardAccessTubitakImpl getSmartCardAccessManager(PKCS11AccessMethod method) throws Exception {

        try {

            if (method == PKCS11AccessMethod.TUBITAK) {
                if (smartCardAccessManager_tubitak == null) {
                    try {
                        smartCardAccessManager_tubitak = new SmartCardAccessTubitakImpl();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
            }

            //smartCardAccessManager_tubitak = new SmartCardAccessTubitakImpl().getInstance();
            return smartCardAccessManager_tubitak;

        } catch (Exception e) {

            throw new Exception("The provided PKCS11 Access Method is not available");
        }
    }
}
