package it.eng.crypto.bean;

import java.util.Calendar;
import java.util.Date;

public class TimeStampValidityBean implements Comparable<TimeStampValidityBean> {

    // Inizio validità
    private Date begin = null;
    // Fine validità
    private Date end = null;
    // Anni di validità
    private int years;

    public int getYears() {
        return years;
    }

    public void setYears(int years) {
        this.years = years;
    }

    public Date getEnd() {
        return end;
    }

    public void setEnd(Date end) {
        this.end = end;
    }

    public Date getBegin() {
        return begin;
    }

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

    @Override
    public String toString() {
        return "begin: " + this.begin + ", end: " + this.end + ", years: " + this.years;
    }
}
