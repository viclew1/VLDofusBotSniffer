package fr.lewon.dofus.bot.sniffer.model.messages.interactive

import fr.lewon.dofus.bot.core.io.stream.ByteArrayReader
import fr.lewon.dofus.bot.sniffer.model.messages.INetworkMessage

open class LeaveDialogMessage : INetworkMessage {

    var dialogType = 0

    override fun deserialize(stream: ByteArrayReader) {
        dialogType = stream.readUnsignedByte()
    }
}