package fr.lewon.dofus.bot.sniffer.model.messages.fight

import fr.lewon.dofus.bot.sniffer.model.messages.INetworkMessage
import fr.lewon.dofus.bot.util.io.stream.ByteArrayReader

class GameFightTurnEndMessage : INetworkMessage {
    override fun deserialize(stream: ByteArrayReader) {
    }
}