/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura.ui;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class AuraTabFactory implements IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;
	
	public AuraTabFactory(IBurpExtenderCallbacks callbacks){
		this.callbacks = callbacks;
	}
	
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new AuraTab(controller, editable,this.callbacks);
	}

}
