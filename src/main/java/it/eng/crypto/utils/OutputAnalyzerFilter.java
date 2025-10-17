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

package it.eng.crypto.utils;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import it.eng.crypto.controller.bean.OutputSignerBean;

public class OutputAnalyzerFilter {

    private static List<String> defaultOutputProperties;
    public List<String> acceptedOutputs;

    static {
	Field[] outputFields = OutputSignerBean.class.getFields();
	if (outputFields != null) {
	    OutputSignerBean tmpOutput = new OutputSignerBean();
	    defaultOutputProperties = new ArrayList<String>();
	    for (Field field : outputFields) {
		if (field.getType().isAssignableFrom(String.class)) {
		    try {
			defaultOutputProperties.add((String) field.get(tmpOutput));
		    } catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		    } catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		    }
		}
	    }
	}

    }

    public OutputAnalyzerFilter() {
	this.acceptedOutputs = new ArrayList<String>();
	if (defaultOutputProperties != null) {
	    for (String defaultOutputProperty : defaultOutputProperties) {
		acceptedOutputs.add(defaultOutputProperty);
	    }
	}
    }

    public void acceptOutput(String acceptedOutput) {
	if (defaultOutputProperties.contains(acceptedOutput)
		&& !acceptedOutputs.contains(acceptedOutput)) {
	    acceptedOutputs.add(acceptedOutput);
	}
    }

    public void filterOutput(String filteredOutput) {
	if (defaultOutputProperties.contains(filteredOutput)
		&& acceptedOutputs.contains(filteredOutput)) {
	    acceptedOutputs.remove(filteredOutput);
	}
    }

    public void acceptsOutputs(String[] newAcceptedOutputs) {
	if (newAcceptedOutputs != null) {
	    for (String newAcceptedOutput : newAcceptedOutputs) {
		acceptOutput(newAcceptedOutput);
	    }
	}
    }

    public void filterOutputs(String[] filteredOutputs) {
	if (filteredOutputs != null) {
	    for (String filteredOutput : filteredOutputs) {
		filterOutput(filteredOutput);
	    }
	}
    }

    public boolean isAcceptedOutput(String output) {
	return acceptedOutputs.contains(output);
    }

    public boolean areAcceptedOutputs(String[] outputs) {
	if (outputs != null) {
	    for (String output : outputs) {
		if (!isAcceptedOutput(output)) {
		    return false;
		}
	    }
	}
	return true;
    }
}
