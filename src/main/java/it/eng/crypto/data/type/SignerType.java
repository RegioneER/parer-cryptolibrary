/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna
 * <p/>
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Affero General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 * <p/>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package it.eng.crypto.data.type;

/**
 * Definisce la lista dei possibili formati di firma digitale
 * 
 * @author Administrator
 *
 */
public enum SignerType {
    P7M, CADES_BES, CADES_T, CADES_C, CADES_X_Long, XML_DSIG, XADES, XADES_BES, XADES_T, XADES_C, XADES_X, XADES_XL,
    PDF_DSIG, PADES, PADES_BES, PADES_T, PADES_C, TSR, M7M, P7S, TSD
}
