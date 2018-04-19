/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.jahia.esigate.hybrissso;

import org.apache.http.Header;
import org.esigate.Driver;
import org.esigate.events.Event;
import org.esigate.events.EventDefinition;
import org.esigate.events.EventManager;
import org.esigate.events.IEventListener;
import org.esigate.events.impl.FragmentEvent;
import org.esigate.extension.Extension;
import org.esigate.util.Parameter;
import org.esigate.util.ParameterString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Properties;

public class HybrisAuthenticationHandler implements IEventListener, Extension {
    // Configuration properties names
    private static final Logger LOG = LoggerFactory.getLogger(HybrisAuthenticationHandler.class);
    private Driver driver;

    @Override
    public boolean event(EventDefinition id, Event event) {
        if (EventManager.EVENT_FRAGMENT_POST.equals(id)) {
            FragmentEvent fetchEvent = (FragmentEvent) event;
            if (fetchEvent.getHttpResponse().containsHeader("Cio-Catalog-Mount-Path")) {
                Header firstHeader = fetchEvent.getHttpResponse().getFirstHeader("Cio-Catalog-Mount-Path");
                LOG.info(firstHeader.getName() + ":" + firstHeader.getValue());
                fetchEvent.getOriginalRequest().getSession()
                        .setAttribute("Cio-Catalog-Mount-Path", firstHeader.getValue());
            }
            if (fetchEvent.getHttpResponse().containsHeader("Cio-Product-Url-Prefix")) {
                Header firstHeader = fetchEvent.getHttpResponse().getFirstHeader("Cio-Product-Url-Prefix");
                LOG.info(firstHeader.getName() + ":" + firstHeader.getValue());
                fetchEvent.getOriginalRequest().getSession()
                        .setAttribute("Cio-Product-Url-Prefix", firstHeader.getValue());
            }
            if (fetchEvent.getHttpResponse().containsHeader("Cio-Dx-Locale")) {
                Header firstHeader = fetchEvent.getHttpResponse().getFirstHeader("Cio-Dx-Locale");
                LOG.info(firstHeader.getName() + ":" + firstHeader.getValue());
                fetchEvent.getOriginalRequest().getSession().setAttribute("Cio-Dx-Locale", firstHeader.getValue());
            }
            if (fetchEvent.getHttpResponse().containsHeader("Hybris-Token")) {
                Header firstHeader = fetchEvent.getHttpResponse().getFirstHeader("Hybris-Token");
                LOG.info(firstHeader.getName() + ":" + firstHeader.getValue());
                fetchEvent.getOriginalRequest().getSession().setAttribute("Hybris-Token", firstHeader.getValue());
            }
        } else if (EventManager.EVENT_FRAGMENT_PRE.equals(id)) {
            FragmentEvent fetchEvent = (FragmentEvent) event;
            LOG.info(fetchEvent.toString());
            Serializable attribute = fetchEvent.getOriginalRequest().getSession().getAttribute("Hybris-Token");
            if (attribute != null && !"invalid".equalsIgnoreCase(attribute.toString())) {
                fetchEvent.getHttpRequest().addHeader("Authorization", "Bearer " + attribute.toString());
            }
            attribute = fetchEvent.getOriginalRequest().getSession().getAttribute("Cio-Catalog-Mount-Path");
            if (attribute != null && !"invalid".equalsIgnoreCase(attribute.toString())) {
                fetchEvent.getHttpRequest().addHeader("Cio-Catalog-Mount-Path", attribute.toString());
            }

            attribute = fetchEvent.getOriginalRequest().getSession().getAttribute("Cio-Product-Url-Prefix");
            if (attribute != null && !"invalid".equalsIgnoreCase(attribute.toString())) {
                fetchEvent.getHttpRequest().addHeader("Cio-Product-Url-Prefix", attribute.toString());
            }

            attribute = fetchEvent.getOriginalRequest().getSession().getAttribute("Cio-Dx-Locale");
            if (attribute != null && !"invalid".equalsIgnoreCase(attribute.toString())) {
                fetchEvent.getHttpRequest().addHeader("Cio-Dx-Locale", attribute.toString());
            }
        }
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.esigate.extension.Extension#init(org.esigate.Driver, java.util.Properties)
     */
    @Override
    public final void init(Driver d, Properties properties) {
        this.driver = d;
        this.driver.getEventManager().register(EventManager.EVENT_FRAGMENT_PRE, this);
        this.driver.getEventManager().register(EventManager.EVENT_FRAGMENT_POST, this);
        LOG.warn("HybrisAuthenticationHandler initialized");
    }

}