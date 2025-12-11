/*
 * Engineering Ingegneria Informatica S.p.A.
 *
 * Copyright (C) 2023 Regione Emilia-Romagna <p/> This program is free software: you can
 * redistribute it and/or modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version. <p/> This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Affero General Public License for more details. <p/> You should
 * have received a copy of the GNU Affero General Public License along with this program. If not,
 * see <https://www.gnu.org/licenses/>.
 */

package it.eng.crypto.controller.bean;

import java.util.Calendar;
import java.util.Date;

/**
 * Bean contenente le informazioni sul periodo di validità di una marca temporale. Detto T il
 * momento di applicazione della marca temporale, questa risulta valida se:<br/>
 * begin &le; T &lt; end AND T + years &ge; [Data Attuale]
 *
 * @author Stefano Zennaro
 *
 */
public class TimeStampValidityBean implements Comparable<TimeStampValidityBean> {

    private Date begin = null;
    private Date end = null;
    private int years;

    /**
     * Recupera la durata della validità in anni
     *
     * @return
     */
    public int getYears() {
        return years;
    }

    /**
     * Definisce la durata della validità in anni
     *
     * @param years
     */
    public void setYears(int years) {
        this.years = years;
    }

    /**
     * Recupera la data di scadenza del tipo di marca temporale
     *
     * @return
     */
    public Date getEnd() {
        return end;
    }

    /**
     * Definisce la data di scadenza del tipo di marca temporale
     *
     * @param end
     */
    public void setEnd(Date end) {
        this.end = end;
    }

    /**
     * Recupera la data di entrata in vigore del tipo di marca temporale
     *
     * @return
     */
    public Date getBegin() {
        return begin;
    }

    /**
     * Definisce la data di entrata in vigore del tipo di marca temporale
     *
     * @param begin
     */
    public void setBegin(Date begin) {
        this.begin = begin;
    }

    public int compareTo(TimeStampValidityBean o) {
        Calendar cal1 = Calendar.getInstance();
        Calendar cal2 = Calendar.getInstance();
        if (o == null) {
            return 1;
        }
        if (this.begin == null) {
            if (o.begin == null) {
                if (this.end == null) {
                    if (o.end == null) {
                        return 0;
                    } else {
                        return 1;
                    }
                } else {
                    if (o.end == null) {
                        return -1;
                    } else {
                        cal1.setTime(this.end);
                        cal2.setTime(o.end);
                        return cal1.before(cal2) ? -1 : 1;
                    }
                }
            } else {
                return -1;
            }
        } else {
            if (o.begin == null) {
                return 1;
            } else {
                cal1.setTime(this.begin);
                cal2.setTime(o.begin);
                return cal1.before(cal2) ? -1 : 1;
            }
        }
    }

    public String toString() {
        return "begin: " + this.begin + ", end: " + this.end + ", years: " + this.years;
    }
}
