/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package aura.ui;

import burp.BurpExtender;
import burp.IHttpService;
import burp.IRequestInfo;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * Static utility methods 
 * 
 * @author adetlefsen
 */
public class Utils {

    public static URL getRequestUrl(IHttpService service, byte[] content) {
        IRequestInfo request = BurpExtender.getHelpers().analyzeRequest(service, content);
        return request.getUrl();
    }

    public static String urlDecode(String input) {
        try {
            return URLDecoder.decode(input, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new AssertionError("UTF-8 not supported", ex);
        }
    }

    public static String urlEncode(String input) {
        try {
            return URLEncoder.encode(input, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new AssertionError("UTF-8 not supported", ex);
        }
    }
    
}
