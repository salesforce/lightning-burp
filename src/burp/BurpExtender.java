/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package burp;
import aura.ui.AuraJSONTabFactory;
import aura.ui.AuraTabFactory;

public class BurpExtender implements IBurpExtender {
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		System.out.printf("\n--\nAura parser\n--\n");
		
		callbacks.setExtensionName("Improved Lightning Burp");
		AuraTabFactory auraFactory = new AuraTabFactory(callbacks);
		callbacks.registerMessageEditorTabFactory(auraFactory);
		
		AuraJSONTabFactory auraMessageFactory = new AuraJSONTabFactory(callbacks, "message", "Aura Message");
		callbacks.registerMessageEditorTabFactory(auraMessageFactory);

		AuraJSONTabFactory auraContextFactory = new AuraJSONTabFactory(callbacks, "aura.context", "Aura Context");
		callbacks.registerMessageEditorTabFactory(auraContextFactory);
	}
}
