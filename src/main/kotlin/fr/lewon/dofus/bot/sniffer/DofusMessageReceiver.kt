package fr.lewon.dofus.bot.sniffer

import fr.lewon.dofus.bot.core.io.stream.ByteArrayReader
import fr.lewon.dofus.bot.core.logs.VldbLogger
import fr.lewon.dofus.bot.sniffer.managers.MessageIdByName
import fr.lewon.dofus.bot.sniffer.store.EventStore

import org.apache.commons.codec.binary.Hex

import org.pcap4j.core.*
import org.pcap4j.core.BpfProgram.BpfCompileMode
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.packet.TcpPacket

import java.net.InetAddress
import java.net.NetworkInterface
import java.util.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.locks.ReentrantLock

class DofusMessageReceiver(private val networkInterfaceName: String? = null) : Thread() {

    companion object {
        private const val BIT_RIGHT_SHIFT_LEN_PACKET_ID = 2
        private const val BIT_MASK = 3
    }

    private val lock = ReentrantLock(true)
    private val handle: PcapHandle
    private val packetListener: PacketListener
    private val packetTreatmentTimer = Timer()
    private val packetsToTreat = ArrayBlockingQueue<TcpPacket>(50)
    private val hostStateByConnection = HashMap<DofusConnection, HostState>()
    private val dofusConnectionByHostPort = HashMap<String, DofusConnection>()

    init {
        val nif = findActiveDevice()
        handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, -1)
        updateFilter()
        packetListener = PacketListener { ethernetPacket ->
            val ipV4Packet = ethernetPacket.payload
            if (ipV4Packet != null) {
                val tcpPacket = ipV4Packet.payload
                if (tcpPacket != null) {
                    if (tcpPacket.payload != null) {
                        packetsToTreat.add(tcpPacket as TcpPacket)
                        packetTreatmentTimer.schedule(buildReceiveTimerTask(), 250L)
                    }
                }
            }
        }
    }

    fun startListening(dofusConnection: DofusConnection, eventStore: EventStore, logger: VldbLogger) {
        try {
            lock.lockInterruptibly()
            stopListening(dofusConnection.hostPort)
            dofusConnectionByHostPort[dofusConnection.hostPort] = dofusConnection
            hostStateByConnection[dofusConnection] = HostState(dofusConnection, eventStore, logger)
            updateFilter()
        } finally {
            lock.unlock()
        }
    }

    fun stopListening(hostPort: String) {
        try {
            lock.lockInterruptibly()
            dofusConnectionByHostPort.remove(hostPort)?.let {
                hostStateByConnection.remove(it)
            }
            updateFilter()
        } finally {
            lock.unlock()
        }
    }

    private fun updateFilter() {
        val filter = if (dofusConnectionByHostPort.isEmpty()) {
            "src host 255.255.255.255 and dst host 255.255.255.255"
        } else {
            buildFilter()
        }
        handle.setFilter(filter, BpfCompileMode.OPTIMIZE)
    }

    private fun buildFilter(): String {
        val srcHostPart = dofusConnectionByHostPort.values.map { it.serverIp }.joinToString(" or ") { "src host $it" }
        val srcPortPart = dofusConnectionByHostPort.values.map { it.serverPort }.joinToString(" or ") { "src port $it" }
        val dstHostPart = dofusConnectionByHostPort.values.map { it.hostIp }.joinToString(" or ") { "dst host $it" }
        val dstPortPart = dofusConnectionByHostPort.values.map { it.hostPort }.joinToString(" or ") { "dst port $it" }
        return "($srcHostPart) and ($srcPortPart) and ($dstHostPart) and ($dstPortPart)"
    }

    override fun run() {
        try {
            handle.loop(-1, packetListener)
        }
        catch (ex: PcapNativeException) {
        }
        catch (ex: InterruptedException) {
        }
        catch (ex: NotOpenException) {
        }
    }

    override fun interrupt() {
        handle.breakLoop()
        handle.close()
        packetTreatmentTimer.cancel()
        packetsToTreat.clear()
    }

    fun isSnifferRunning(): Boolean {
        return isAlive && handle.isOpen
    }

    private fun buildReceiveTimerTask(): TimerTask {
        return object : TimerTask() {
            override fun run() {
                lock.lockInterruptibly()
                val tcpPacket = packetsToTreat.minByOrNull { it.header.sequenceNumberAsLong }
                    ?: error("No TCP packet to treat")
                packetsToTreat.remove(tcpPacket)

                val hostPortStr = tcpPacket.header.dstPort.valueAsString()
                val dofusConnection = dofusConnectionByHostPort[hostPortStr]
                    ?: error("Unknown connection for port : $hostPortStr")
                val hostState = hostStateByConnection[dofusConnection]
                    ?: error("Unknown host state for port : $hostPortStr")

                val rawData = hostState.leftoverBuffer + tcpPacket.payload.rawData
                val leftoverStr = Hex.encodeHexString(hostState.leftoverBuffer)
                hostState.leftoverBuffer = ByteArray(0)
                try {
                    receiveData(hostState, ByteArrayReader(rawData))
                } catch (t: Throwable) {
                    t.printStackTrace()
                    val rawDataStr = Hex.encodeHexString(rawData)
                    println("Couldn't receive data (leftover : $leftoverStr) : $rawDataStr")
                    hostState.logger.error("Couldn't receive data (leftover : $leftoverStr) : $rawDataStr")
                } finally {
                    lock.unlock()
                }
            }
        }
    }

    /** Find the current active pcap network interface.
     * @return The active pcap network interface
     */
    private fun findActiveDevice(): PcapNetworkInterface {
        var currentAddress: InetAddress? = null
        val nis = NetworkInterface.getNetworkInterfaces()
        while (nis.hasMoreElements() && currentAddress == null) {
            val ni = nis.nextElement()
            if (ni.isUp && !ni.isLoopback) {
                val ias = ni.inetAddresses

                while (ias.hasMoreElements() && currentAddress == null) {
                    val ia = ias.nextElement()

                    if (ia.isSiteLocalAddress &&
                        !ia.isLoopbackAddress &&
                        !ni.displayName.contains("VMnet") ||
                        (networkInterfaceName != null && ni.displayName == networkInterfaceName)) {
                        currentAddress = ia
                    }
                }
            }
        }
        currentAddress ?: error("No active address found. Make sure you have an internet connection.")
        return Pcaps.getDevByAddress(currentAddress)
            ?: error("No active device found. Make sure WinPcap or libpcap is installed.")
    }

    fun receiveData(hostState: HostState, data: ByteArrayReader) {
        if (data.available() > 0) {
            var messagePremise = lowReceive(hostState, data)
            while (messagePremise != null) {
                process(messagePremise, hostState)
                messagePremise = lowReceive(hostState, data)
            }
        }
    }

    private fun process(messagePremise: DofusMessagePremise, hostState: HostState) {
        val untreatedStr = if (messagePremise.eventClass == null) "[UNTREATED] " else ""
        hostState.logger.info("${untreatedStr}Message received : [${messagePremise.eventName}:${messagePremise.eventId}]")
        messagePremise.eventClass?.getConstructor()?.newInstance()
            ?.also { it.deserialize(messagePremise.stream) }
            ?.let { hostState.eventStore.addSocketEvent(it, hostState.connection) }
    }

    private fun lowReceive(hostState: HostState, src: ByteArrayReader): DofusMessagePremise? {
        if (!hostState.splitPacket) {
            if (src.available() < 2) {
                hostState.leftoverBuffer = src.readAllBytes()
                return null
            }
            val header = src.readUnsignedShort()
            val messageId = header shr BIT_RIGHT_SHIFT_LEN_PACKET_ID
            if (src.available() >= (header and BIT_MASK)) {
                val messageLength = readMessageLength(header, src)
                if (MessageIdByName.getName(messageId) == null) {
                    error("No message for messageId $messageId / header : $header / length : $messageLength")
                }
                if (src.available() >= messageLength) {
                    return DofusMessageReceiverUtil.parseMessagePremise(
                        ByteArrayReader(src.readNBytes(messageLength)),
                        messageId
                    )
                }
                hostState.staticHeader = -1
                hostState.splitPacketLength = messageLength
                hostState.splitPacketId = messageId
                hostState.splitPacket = true
                hostState.inputBuffer = src.readNBytes(src.available())
                return null
            }
            if (MessageIdByName.getName(messageId) == null) {
                error("No message for messageId $messageId / header : $header")
            }
            hostState.staticHeader = header
            hostState.splitPacketLength = 0
            hostState.splitPacketId = messageId
            hostState.splitPacket = true
            return null
        }
        if (hostState.staticHeader != -1) {
            hostState.splitPacketLength = readMessageLength(hostState.staticHeader, src)
            hostState.staticHeader = -1
        }
        if (src.available() + hostState.inputBuffer.size >= hostState.splitPacketLength) {
            hostState.inputBuffer += src.readNBytes(hostState.splitPacketLength - hostState.inputBuffer.size)
            val inputBufferReader = ByteArrayReader(hostState.inputBuffer)
            val msg = DofusMessageReceiverUtil.parseMessagePremise(inputBufferReader, hostState.splitPacketId)
            hostState.splitPacket = false
            hostState.inputBuffer = ByteArray(0)
            return msg
        }
        hostState.inputBuffer += src.readAllBytes()
        return null
    }

    private fun readMessageLength(staticHeader: Int, src: ByteArrayReader): Int {
        return when (staticHeader and BIT_MASK) {
            0 -> 0
            1 -> src.readUnsignedByte()
            2 -> src.readUnsignedShort()
            3 -> ((src.readUnsignedByte() and 255) shl 16) + ((src.readUnsignedByte() and 255) shl 8) + (src.readUnsignedByte() and 255)
            else -> error("Invalid length")
        }
    }

}