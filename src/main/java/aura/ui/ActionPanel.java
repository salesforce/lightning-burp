/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura.ui;

import javax.swing.JPanel;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITextEditor;

@SuppressWarnings("serial")
public class ActionPanel extends JPanel {
	public ITextEditor textEditor;
	
	public ActionPanel(){
		this.textEditor = BurpExtender.getCallbacks().createTextEditor();
	}
	
	public byte[] getSelectedText(){
		return textEditor.getSelectedText();
	}
}
