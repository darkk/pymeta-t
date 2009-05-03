#!/usr/bin/python
# -*- encoding: utf-8 -*-

# Copyright (C) 2009 Leonid Evdokimov <leon@darkk.net.ru>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from zope.interface import implements

from twisted.internet import defer
from twisted.application import service, strports
from twisted.words.protocols.jabber.jid import JID

from wokkel import component, disco
from wokkel.subprotocols import XMPPHandler
from wokkel.generic import FallbackHandler

class JIDNAT(object):
    # That should be rendered at '@' according to XEP-0106 (JID Escaping)
    delim = u'\\40'

    def __init__(self, service_jid):
        assert service_jid.user is None and service_jid.resource is None
        self.jid = service_jid

    def nat(self, orig):
        """
        luser@example.org/res -> luser\\40example.org@this.service/res
        srv.example.org       -> srv.example.org@this.service
        """
        return JID(tuple=(
            (orig.user + self.delim + orig.host) if orig.user is not None else orig.host,
            self.jid.host,
            orig.resource
            ))

    def denat(self, nated):
        assert nated.host == self.jid.host
        l = nated.user.rsplit(self.delim, 1)
        if len(l) == 1:
            user, host = None, l[0]
        else:
            user, host = l[0], l[1]
        return JID(tuple=(user, host, nated.resource))


class DiscoProxy(XMPPHandler):
    implements(disco.IDisco)

    def __init__(self, service_jid, disco_client, jidnat):
        assert service_jid.user is None and service_jid.resource is None
        self.jid = service_jid
        self.disco_client = disco_client
        self.jidnat = jidnat
        self._parent_jid = JID(service_jid.host.split('.', 1)[1])

    def getDiscoInfo(self, requestor, target, nodeIdentifier):
        if target == self.jid:
            if not nodeIdentifier:
                return defer.succeed([
                    disco.DiscoIdentity('component', 'generic', 'XMPP-NAT component'),
                    disco.DiscoFeature(disco.NS_DISCO_INFO),
                    disco.DiscoFeature(disco.NS_DISCO_ITEMS),
                ])
            else:
                return defer.succeed([])
        else:
            return self.disco_client.requestInfo(self.jidnat.denat(target),
                                                 nodeIdentifier,
                                                 self.jidnat.nat(requestor))

    def getDiscoItems(self, requestor, target, nodeIdentifier):
        if target == self.jid:
            d = self.disco_client.requestItems(self._parent_jid,
                                               nodeIdentifier,
                                               self.jidnat.nat(requestor))
            def cb(disco_items):
                return [disco.DiscoItem(self.jidnat.nat(item.entity), item.nodeIdentifier, item.name)
                        for item in disco_items if item.entity != self.jid]
            d.addCallback(cb)
            return d
        else:
            return self.disco_client.requestItems(self.jidnat.denat(target),
                                                  nodeIdentifier,
                                                  self.jidnat.nat(requestor))


class StanzaNAT(XMPPHandler):
    def __init__(self, jidnat):
        XMPPHandler.__init__(self)
        self.jidnat = jidnat

    def connectionInitialized(self):
        self.xmlstream.addObserver("/message", self._onStanza)
        self.xmlstream.addObserver("/iq", self._onIqStanza)
        self.xmlstream.addObserver("/presence", self._onStanza)

    def _onStanza(self, stanza):
        if stanza.handled:
            return
        # FIXME: is any loop prevention required?
        orig_from = stanza.getAttribute('from')
        orig_to   = stanza.getAttribute('to')
        new_from = self.jidnat.nat(JID(orig_from)).full()
        new_to   = self.jidnat.denat(JID(orig_to)).full()

        # FIXME: that's neither thread-safe nor exception-safe
        try:
            stanza.attributes['from'] = new_from
            stanza.attributes['to']   = new_to
            self.send(stanza)
        finally:
            stanza.attributes['from'] = orig_from
            stanza.attributes['to']   = orig_to

    def _onIqStanza(self, stanza):
        self._onStanza(stanza)
        stanza.handled = True


class HackedDiscoClientProtocol(XMPPHandler):
    """
    XMPP Service Discovery client protocol.

    Copy-pasted from wokkel.disco to add `requestor' param.
    """

    def requestInfo(self, entity, nodeIdentifier='', requestor=None):
        """
        Request information discovery from a node.

        @param entity: Entity to send the request to.
        @type entity: L{jid.JID}
        @param nodeIdentifier: Optional node to request info from.
        @type nodeIdentifier: C{unicode}
        @param requestor: Optional jid of the requesting party.
        @type requesting: L{jid.JID}
        """

        request = disco._DiscoRequest(self.xmlstream, disco.NS_DISCO_INFO, nodeIdentifier)

        if requestor is not None:
            request['from'] = requestor.full()

        d = request.send(entity.full())
        d.addCallback(lambda iq: disco.DiscoInfo.fromElement(iq.query))
        return d


    def requestItems(self, entity, nodeIdentifier='', requestor=None):
        """
        Request items discovery from a node.

        @param entity: Entity to send the request to.
        @type entity: L{jid.JID}
        @param nodeIdentifier: Optional node to request info from.
        @type nodeIdentifier: C{unicode}
        @param requestor: Optional jid of the requesting party.
        @type requesting: L{jid.JID}
        """

        request = disco._DiscoRequest(self.xmlstream, disco.NS_DISCO_ITEMS, nodeIdentifier)

        if requestor is not None:
            request['from'] = requestor.full()

        d = request.send(entity.full())
        d.addCallback(lambda iq: disco.DiscoItems.fromElement(iq.query))
        return d


def makeComponent(config):
    # Set up component that connects to the Jabber server
    jid = JID(config['jid'])
    comp = component.Component(config['rhost'], config['rport'],
                               jid.host, config['secret'])
    comp.logTraffic = config['verbose']

    disco_client = HackedDiscoClientProtocol()
    disco_client.setHandlerParent(comp)

    jidnat = JIDNAT(jid)

    DiscoProxy(jid, disco_client, jidnat).setHandlerParent(comp)
    disco.DiscoHandler().setHandlerParent(comp)
    StanzaNAT(jidnat).setHandlerParent(comp)
    FallbackHandler().setHandlerParent(comp)

    return comp


if __name__ != '__main__':
    # MAYBE the script was run under twistd
    from config import config
    application = service.Application("XMPP-NAT Component")
    makeComponent(config).setServiceParent(application)
else:
    print "The script should be run under `twistd'."
    print "Example:"
    print "$ twistd --python=pymeta-t.py"

# vim:set tabstop=4 softtabstop=4 shiftwidth=4 expandtab: 
