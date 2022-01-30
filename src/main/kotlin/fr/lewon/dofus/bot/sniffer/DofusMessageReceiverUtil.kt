package fr.lewon.dofus.bot.sniffer

import fr.lewon.dofus.VldbProtocolUpdater
import fr.lewon.dofus.bot.core.io.gamefiles.VldbFilesUtil
import fr.lewon.dofus.bot.core.io.stream.ByteArrayReader
import fr.lewon.dofus.bot.sniffer.managers.MessageIdByName
import fr.lewon.dofus.bot.sniffer.managers.TypeIdByName
import fr.lewon.dofus.bot.sniffer.model.messages.INetworkMessage
import fr.lewon.dofus.export.builder.VldbIdByNameExportPackTaskBuilder
import org.reflections.Reflections
import java.io.File
import java.net.NetworkInterface

object DofusMessageReceiverUtil {

    private lateinit var messagesById: Map<Int, Class<out INetworkMessage>>

    fun parseMessagePremise(stream: ByteArrayReader, messageId: Int): DofusMessagePremise {
        val messageType = messagesById[messageId]
        val messageName = MessageIdByName.getName(messageId) ?: error("No message for id : $messageId")
        return DofusMessagePremise(messageName, messageId, messageType, stream)
    }

    fun prepareNetworkManagers() {
        val gameDir = VldbFilesUtil.getDofusDirectory()
        val swfFile = File(gameDir, "DofusInvoker.swf")
        if (!swfFile.exists() || !swfFile.isFile) {
            throw RuntimeException("Unable to find DofusInvoker.swf in Dofus directory")
        }
        val builders = listOf(
            VldbIdByNameExportPackTaskBuilder("MessageReceiver", MessageIdByName, "_messagesTypes"),
            VldbIdByNameExportPackTaskBuilder("ProtocolTypeManager", TypeIdByName, "_typesTypes")
        )
        VldbProtocolUpdater.updateManagers(swfFile, builders)
        messagesById = Reflections(INetworkMessage::class.java.packageName)
            .getSubTypesOf(INetworkMessage::class.java)
            .associateBy { (MessageIdByName.getId(it.simpleName) ?: error("Couldn't find id for [${it.simpleName}]")) }
    }

    fun getNetworkInterfaceNames(): List<String> {
        val result = mutableListOf<String>()
        val nis = NetworkInterface.getNetworkInterfaces()

        while (nis.hasMoreElements()) {
            val ni = nis.nextElement()
            if (ni.isUp && !ni.isLoopback) {
                result.add(ni.displayName)
            }
        }

        return result
    }
}