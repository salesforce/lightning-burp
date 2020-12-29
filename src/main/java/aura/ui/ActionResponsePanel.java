/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura.ui;

import java.awt.BorderLayout;

import burp.BurpExtender;
import com.codemagi.burp.BaseExtender;
import com.fasterxml.jackson.core.JsonProcessingException;

import aura.ActionResponse;
import burp.IBurpExtenderCallbacks;

@SuppressWarnings("serial")
public class ActionResponsePanel extends ActionPanel {
	private IBurpExtenderCallbacks callbacks;
	
	public ActionResponsePanel(ActionResponse response){
		super();
		this.callbacks = BurpExtender.getCallbacks();
		this.setLayout(new BorderLayout());
		
		this.textEditor = this.callbacks.createTextEditor();
		this.textEditor.setEditable(false);
		try {
			this.textEditor.setText(response.getResponseString().getBytes());
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			BaseExtender.printStackTrace(e);
			this.textEditor.setText("Invalid JSON".getBytes());
		}
		add(this.textEditor.getComponent());
		
		callbacks.customizeUiComponent(this);
	}
}
