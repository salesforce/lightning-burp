/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura.ui;

import burp.*;

public class AuraJSONTabFactory implements IMessageEditorTabFactory {
	
	private IBurpExtenderCallbacks callbacks;
	
	private String auraDataparam;
	private String caption;
	
	public AuraJSONTabFactory(){
		this.callbacks = BurpExtender.getCallbacks();
	}

	public AuraJSONTabFactory(String auraDataparam, String caption) {
		this.callbacks = BurpExtender.getCallbacks();
		this.auraDataparam = auraDataparam;
		this.caption = caption;
	}
	
	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new AuraJSONTab(controller, editable, auraDataparam, caption);
	}

}
