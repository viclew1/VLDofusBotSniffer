package fr.lewon.dofus.bot.sniffer.model.messages.fight

import fr.lewon.dofus.bot.sniffer.model.messages.INetworkMessage
import fr.lewon.dofus.bot.core.io.stream.ByteArrayReader

class GameFightTurnStartPlayingMessage : INetworkMessage {
    override fun deserialize(stream: ByteArrayReader) {
    }
}