# SPDX-FileCopyrightText: 2024 for Google LLC
#
# SPDX-License-Identifier: MIT
#
# USB Power Delivery (PD) Broker/Sniffer using RP2040 PIO
#
# WARNUNG: Dies ist ein fortgeschrittenes Bildungsbeispiel. Es erfordert
# eine korrekt entworfene Analog-Front-End (AFE)-Schaltung zwischen den
# RP2040 GPIOs und der USB-C CC-Leitung. Verbinden Sie GPIOs NIEMALS
# direkt mit einem USB-C-Anschluss. Dies kann Ihre Geräte beschädigen.
#
# HINWEIS: Diese Implementierung ist eine BILDUNGS-REFERENZ.
# Sie implementiert die 5b4b-Protokollschicht, kann aber
# die Echtzeitanforderungen (z.B. GoodCRC-Handshake < 1.5ms)
# in Python NICHT erfüllen und wird nicht mit echter
# Hardware funktionieren.

import board
import rp2pio
import adafruit_pioasm
import time
import struct
import binascii
from microcontroller import pin

# --- Konfiguration ---
RX_PIN = board.GP16
TX_PIN = board.GP17
PIO_FREQ = 12_000_000

# --- USB-PD Konstanten ---
MESSAGE_TYPES = {
    0b00000: "GoodCRC", # GoodCRC ist ein Kontroll-Message-Typ
    0b00001: "Source_Capabilities",
    0b00010: "Request",
    0b00011: "Accept",
    0b00100: "Reject",
    0b00101: "PS_RDY",
    0b00110: "Get_Source_Cap",
    0b01111: "Soft_Reset",
}

# --- USB-PD Physische Schicht-Konstanten ---
# Ref: USB PD Spec, Section 5.3 "Symbol Encoding"

# 4b -> 5b Enkodierungs-Tabelle (Daten)
ENCODE_5B4B = {
    0x0: 0b11110, 0x1: 0b01001, 0x2: 0b10100, 0x3: 0b10101,
    0x4: 0b01010, 0x5: 0b01011, 0x6: 0b01110, 0x7: 0b01111,
    0x8: 0b10010, 0x9: 0b10011, 0xA: 0b10110, 0xB: 0b10111,
    0xC: 0b11010, 0xD: 0b11011, 0xE: 0b11100, 0xF: 0b11101,
}

# 5b -> 4b Dekodierungs-Tabelle (Daten)
DECODE_4B5B = {
    0b11110: 0x0, 0b01001: 0x1, 0b10100: 0x2, 0b10101: 0x3,
    0b01010: 0x4, 0b01011: 0x5, 0b01110: 0x6, 0b01111: 0x7,
    0b10010: 0x8, 0b10011: 0x9, 0b10110: 0xA, 0b10111: 0xB,
    0b11010: 0xC, 0b11011: 0xD, 0b11100: 0xE, 0b11101: 0xF,
}

# K-Codes (Sonderbefehle)
K_CODE_SYNC1 = 0b11000 # SOP*
K_CODE_SYNC2 = 0b00110 # SOP*
K_CODE_SYNC3 = 0b00101 # SOP'' (Debug)
K_CODE_RST1  = 0b00111 # Hard Reset
K_CODE_RST2  = 0b11001 # Hard Reset
K_CODE_EOP   = 0b01101 # End of Packet

# SOP (Start of Packet) Sequenzen
SOP_SEQUENCE = [K_CODE_SYNC1, K_CODE_SYNC1, K_CODE_SYNC1, K_CODE_SYNC2]
SOP_PRIME_SEQUENCE = [K_CODE_SYNC1, K_CODE_SYNC1, K_CODE_SYNC2, K_CODE_SYNC1]
SOP_DOUBLE_PRIME_SEQUENCE = [K_CODE_SYNC1, K_CODE_SYNC2, K_CODE_SYNC1, K_CODE_SYNC1]

# Preamble (64 Bits 1/0 abwechselnd, endet auf 0)
PREAMBLE_BITS = [val for i in range(32) for val in (1, 0)] # 64 Bits [1,0,1,0,...]


# --- PIO Assembler Programme (Korrekturen von zuvor) ---

# PIO Programm zum Empfangen von BMC-kodierten Daten
# KORRIGIERT: Die Logik ist nun korrekt.
# Ein '0'-Bit erzeugt einen kurzen Puls (0.5 UI)
# Ein '1'-Bit erzeugt einen langen Puls (1.0 UI)
pio_bmc_rx_assembler = """
.program usb_pd_bmc_rx
.wrap_target
    wait 1 pin 0        ; Warte auf steigende Flanke (Start '0' oder Mitte '1')
    set x, 29           ; Setze Timer auf 0.75 UI (30 Zyklen bei 12MHz/40)
check_loop:
    jmp pin, pin_is_high
    
    ; --- Pin ist LOW (gefallen vor 0.75 UI)
    ; Muss ein '0'-Bit sein (Pulsdauer 0.5 UI)
    in null, 1          ; Schiebe '0' ins FIFO
    jmp start_over

pin_is_high:
    jmp x--, check_loop ; Warte, bis Timer abläuft

    ; --- Timeout ---
    ; Pin blieb HIGH > 0.75 UI = '1'-Bit (Pulsdauer 1.0 UI)
    set y, 1
    in y, 1             ; Schiebe '1' ins FIFO
    wait 0 pin 0        ; Warte auf das Ende des '1'-Bits (fallende Flanke)

start_over:
.wrap
"""

# PIO Programm zum Senden von BMC-kodierten Daten
pio_bmc_tx_assembler = """
.program usb_pd_bmc_tx
.side_set 1
; X = aktueller Pegel (0=LOW, 1=HIGH), Y = Bit zum Senden

    set x, 0            ; KORREKTUR: X (Pegel) hier auf 0 (LOW) initialisieren

.wrap_target
    pull noblock        
    mov y, osr          ; Bit in Y
    
    jmp y--, send_one   ; Korrektur von vorhin

send_zero:
    mov x, !x           ; Invertiere Pegel (Start-Transition)
send_one:               
    jmp x--, high_part_1  ; Korrektur von vorhin
    
low_part_1:
    ; Korrektur: [19] ist > [15]. 20 Zyklen = 16 + 4
    nop             side 0 [15]
    nop             side 0 [3] 
    jmp mid_bit
high_part_1:
    nop             side 1 [15]
    nop             side 1 [3]
    
mid_bit:
    mov x, !x           ; Invertiere Pegel (Mid-Bit Transition)
    
    jmp x--, high_part_2 ; Korrektur von vorhin

low_part_2:
    nop             side 0 [15]
    nop             side 0 [3]
    jmp end_bit
high_part_2:
    nop             side 1 [15]
    nop             side 1 [3]

end_bit:
.wrap
"""

# --- Hilfsfunktionen für das USB-PD Protokoll ---

def calculate_crc32(data: bytearray) -> int:
    """Software-Implementierung der CRC32 (zu langsam für Echtzeit)."""
    crc = 0xFFFFFFFF
    poly = 0x04C11DB7
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
    return crc & 0xFFFFFFFF

def build_message(msg_type: int, num_data_objects: int, data: bytearray = bytearray()) -> bytearray:
    """Erstellt eine vollständige USB-PD-Nachricht (Header + Daten + CRC)."""
    header = (num_data_objects & 0x7) << 12 | (msg_type & 0x1F)
    header |= (0b01 << 9) # Spec Rev 2.0
    msg_bytes = bytearray(struct.pack('<H', header)) + data
    crc = calculate_crc32(msg_bytes)
    msg_bytes += struct.pack('<I', crc)
    return msg_bytes

def print_parsed_message(num_obj, msg_type, data):
    """Gibt eine formatierte, lesbare Version einer PD-Nachricht aus."""
    msg_name = MESSAGE_TYPES.get(msg_type, f"Unknown (0b{msg_type:05b})")
    print(f"✅ Nachricht: {msg_name} ({num_obj} Datenobjekte)")
    
    if msg_type == MESSAGE_TYPES.get("GoodCRC"):
        return # Nichts weiter zu drucken

    if msg_type == MESSAGE_TYPES.get("Source_Capabilities"):
        for i in range(num_obj):
            pdo = struct.unpack('<I', data[i*4 : (i+1)*4])[0]
            if (pdo >> 30) == 0b00: # Fixed Supply
                voltage_mv = ((pdo >> 10) & 0x3FF) * 50
                current_ma = (pdo & 0x3FF) * 10
                print(f"  - PDO {i+1} (Fixed): {voltage_mv / 1000:.2f}V @ {current_ma / 1000:.2f}A")
    elif msg_type == MESSAGE_TYPES.get("Request"):
        rdo = struct.unpack('<I', data)[0]
        obj_pos = (rdo >> 28) & 0x7
        op_current_ma = ((rdo >> 10) & 0x3FF) * 10
        print(f"  - RDO: Fordere PDO an Position {obj_pos} mit {op_current_ma} mA an.")


# --- NEU: Physical Layer Helper ---

def symbols_to_bits(symbols: list) -> list:
    """Wandelt eine Liste von 5-Bit-Symbolen in eine flache Bit-Liste um."""
    bits = []
    for symbol in symbols:
        for i in range(5):
            bits.append((symbol >> (4-i)) & 1)
    return bits

def encode_message_to_bits(message: bytearray) -> list:
    """
    Wandelt eine vollständige Nachricht (Header+Daten+CRC)
    in 5b4b-kodierte Bits um (ohne Preamble/SOP/EOP).
    """
    bits = []
    for byte in message:
        # Oberes Nibble
        nibble_hi = (byte >> 4) & 0x0F
        symbol_hi = ENCODE_5B4B[nibble_hi]
        bits.extend(symbols_to_bits([symbol_hi]))
        
        # Unteres Nibble
        nibble_lo = byte & 0x0F
        symbol_lo = ENCODE_5B4B[nibble_lo]
        bits.extend(symbols_to_bits([symbol_lo]))
    return bits

def decode_bits_to_message(bits: list) -> (bytearray, bool, bool):
    """
    Wandelt eine Liste von 5b4b-kodierten Bits (ohne SOP/EOP) in Bytes um.
    Gibt zurück: (daten, decode_ok, eop_gefunden)
    """
    if len(bits) % 5 != 0:
        print("Decode Error: Bit-Anzahl nicht durch 5 teilbar.")
        return None, False, False

    nibbles = []
    for i in range(0, len(bits), 5):
        symbol = 0
        for j in range(5):
            symbol |= bits[i+j] << (4-j)
        
        if symbol == K_CODE_EOP:
            # EOP gefunden
            return None, True, True 

        if symbol not in DECODE_4B5B:
            print(f"Decode Error: Unbekanntes Symbol {symbol:05b}")
            return None, False, False
        
        nibbles.append(DECODE_4B5B[symbol])

    if len(nibbles) % 2 != 0:
        # Sollte nicht passieren, wenn EOP korrekt behandelt wird
        print("Decode Error: Ungerade Anzahl von Nibbles.")
        return None, False, False

    msg_bytes = bytearray()
    for i in range(0, len(nibbles), 2):
        byte = (nibbles[i] << 4) | nibbles[i+1]
        msg_bytes.append(byte)
        
    return msg_bytes, True, False


# --- Hauptklasse für USB-PD Broker ---

class USBPDBroker:
    def __init__(self, rx_pin, tx_pin):
        self.sm_rx = rp2pio.StateMachine(
            adafruit_pioasm.assemble(pio_bmc_rx_assembler),
            frequency=PIO_FREQ,
            first_in_pin=rx_pin,
            jmp_pin=rx_pin,
            in_shift_right=False,
            auto_push=True, push_threshold=32
        )
        self.sm_tx = rp2pio.StateMachine(
            adafruit_pioasm.assemble(pio_bmc_tx_assembler),
            frequency=PIO_FREQ, first_sideset_pin=tx_pin,
            auto_pull=True, pull_threshold=1
        )
        
        # Pre-berechnete Bit-Sequenzen für die SOP-Suche
        self.SOP_BITS = symbols_to_bits(SOP_SEQUENCE)
        self.EOP_BITS = symbols_to_bits([K_CODE_EOP])

        print("✅ PIO State Machines initialisiert (mit korrigierter Logik).")

    def deinit(self):
        """Räumt die State Machines auf."""
        self.sm_rx.deinit()
        self.sm_tx.deinit()
        print("\n⏹️ PIO State Machines gestoppt.")

    def _send_bits(self, bits: list):
        """Schreibt eine Bit-Liste an den TX PIO."""
        # Dies ist langsam in Python, aber demonstriert die Logik
        for bit in bits:
            self.sm_tx.write(struct.pack('<I', bit))

    def _send_packet(self, sop_sequence: list, message: bytearray):
        """
        Sendet ein vollständiges, kodiertes Paket.
        (Preamble -> SOP -> 5b4b-Daten -> EOP)
        """
        # 1. Preamble
        self._send_bits(PREAMBLE_BITS)
        
        # 2. SOP
        self._send_bits(symbols_to_bits(sop_sequence))
        
        # 3. 5b4b-kodierte Nachricht (Header+Daten+CRC)
        data_bits = encode_message_to_bits(message)
        self._send_bits(data_bits)
        
        # 4. EOP
        self._send_bits(self.EOP_BITS)
        
        # 5. TX PIO leeren/zurücksetzen
        time.sleep(0.001) # Warten, bis Puffer gesendet wurde
        
    def _send_goodcrc(self):
        """Baut und sendet eine GoodCRC-Nachricht."""
        # GoodCRC ist eine Kontroll-Nachricht ohne Datenobjekte
        # (Header ist 2 Bytes, CRC ist 4 Bytes)
        print("Sende GoodCRC...")
        msg_bytes = build_message(MESSAGE_TYPES.get("GoodCRC"), 0)
        self._send_packet(SOP_SEQUENCE, msg_bytes)

    # --- Haupt-Sende- und Empfangsfunktionen ---
    
    def send_message(self, message: bytearray, sop_type=SOP_SEQUENCE) -> bool:
        """
        Sendet eine Nachricht und wartet auf GoodCRC.
        Gibt True zurück, wenn GoodCRC empfangen wurde.
        """
        hex_string = binascii.hexlify(message).decode()
        print(f"Sende Paket ({len(message)} Bytes): {hex_string}")
        
        self._send_packet(sop_type, message)
        
        # --- HIER BEGINNT DAS ECHTZEIT-PROBLEM ---
        # Wir müssen *sofort* auf ein GoodCRC lauschen.
        
        # Warten auf tReceive (ca. 1.5ms)
        # In Python wird dieses Timeout fast immer eintreten,
        # bevor der Partner überhaupt antworten konnte, ODER
        # wir verpassen die Antwort, weil unser eigener Code zu langsam ist.
        num_obj, msg_type, data, ok = self.read_message(timeout=0.002) 
        
        if ok and msg_type == MESSAGE_TYPES.get("GoodCRC"):
            print("GoodCRC empfangen.")
            return True
        else:
            print("❌ Fehler: Kein GoodCRC empfangen (Timeout oder falsche Antwort).")
            return False

    def read_message(self, timeout=1.0) -> (int, int, bytearray, bool):
        """
        Liest, dekodiert und validiert eine vollständige PD-Nachricht.
        """
        start_time = time.monotonic()
        bit_buffer = []
        
        STATE_HUNTING_SOP = 0
        STATE_READING_MSG = 1
        state = STATE_HUNTING_SOP
        
        msg_bits = []

        while time.monotonic() - start_time < timeout:
            # 1. Bits aus dem PIO sammeln
            while self.sm_rx.in_waiting > 0:
                data_word = self.sm_rx.read(1)[0]
                for i in range(32):
                    bit_buffer.append((data_word >> (31 - i)) & 1)
            
            # 2. Protokoll-State-Machine
            if state == STATE_HUNTING_SOP:
                # Suche nach der SOP-Sequenz im Puffer
                try:
                    # (str.find ist eine schnelle Methode, Bit-Listen zu durchsuchen)
                    sop_str = "".join(map(str, self.SOP_BITS))
                    buf_str = "".join(map(str, bit_buffer))
                    
                    idx = buf_str.find(sop_str)
                    if idx != -1:
                        print("SOP gefunden!")
                        state = STATE_READING_MSG
                        # Alles nach dem SOP behalten
                        bit_buffer = bit_buffer[idx + len(self.SOP_BITS):]
                        msg_bits = [] # Nachrichtenpuffer löschen
                    else:
                        # Puffer kürzen, um nicht ewig zu suchen
                        if len(bit_buffer) > 256:
                            bit_buffer = bit_buffer[128:]
                except MemoryError:
                    print("Speicherfehler bei Puffer-Suche, setze zurück.")
                    bit_buffer = []

            elif state == STATE_READING_MSG:
                # Sammle Bits, bis EOP gefunden wird
                try:
                    eop_str = "".join(map(str, self.EOP_BITS))
                    buf_str = "".join(map(str, bit_buffer))
                    idx = buf_str.find(eop_str)
                    
                    if idx != -1:
                        print("EOP gefunden!")
                        msg_bits.extend(bit_buffer[:idx]) # Bits vor EOP
                        bit_buffer = bit_buffer[idx + len(self.EOP_BITS):] # Rest behalten
                        
                        # --- NACHRICHT IST KOMPLETT, JETZT DEKODIEREN ---
                        msg_bytes, decode_ok, _ = decode_bits_to_message(msg_bits)
                        if not decode_ok:
                            print("❌ 5b4b Dekodierfehler.")
                            state = STATE_HUNTING_SOP
                            continue

                        if len(msg_bytes) < 6: # (2B Header + 4B CRC)
                            print("❌ Paket-Längenfehler.")
                            state = STATE_HUNTING_SOP
                            continue
                            
                        # --- CRC-Prüfung ---
                        header_data = msg_bytes[:-4]
                        crc_received_bytes = msg_bytes[-4:]
                        crc_received = struct.unpack('<I', crc_received_bytes)[0]
                        
                        
                        # --- ANFANG: Auskommentierter MicroPython-Code für Hardware-CRC32 ---
                        #
                        # In CircuitPython rufen wir die langsame Software-Funktion auf:
                        #   crc_calculated = calculate_crc32(header_data)
                        #
                        # In MicroPython würden wir stattdessen die Hardware nutzen.
                        # Der folgende Code (nur als Kommentar) zeigt, wie man
                        # den DMA-Sniffer des RP2040 für eine extrem schnelle
                        # CRC32-Berechnung konfigurieren würde.
                        
                        # import rp2
                        # import uctypes
                        # from machine import mem32
                        #
                        # # Adressen der Peripheriegeräte
                        # DMA_BASE = 0x50000000
                        # SIO_BASE = 0xd0000000
                        #
                        # # Ein "Wegwerf"-Register, zu dem der DMA schreiben kann
                        # SIO_FIFO_W = SIO_BASE + 0x54 
                        #
                        # def get_hw_crc32(data_buffer: bytearray) -> int:
                        #     """Berechnet CRC32 mit DMA-Sniffer."""
                        #
                        #     # Wir nehmen an, DMA-Kanal 0 ist frei
                        #     chan = 0 
                        #     DMA_CHAN_BASE = DMA_BASE + chan * 0x40
                        #
                        #     # Register-Offsets für Kanal 0
                        #     READ_ADDR   = DMA_CHAN_BASE + 0x00
                        #     WRITE_ADDR  = DMA_CHAN_BASE + 0x04
                        #     TRANS_COUNT = DMA_CHAN_BASE + 0x08
                        #     CTRL_TRIG   = DMA_CHAN_BASE + 0x0C
                        #     SNIFF_CTRL  = DMA_CHAN_BASE + 0x18
                        #     SNIFF_DATA  = DMA_CHAN_BASE + 0x1C
                        #
                        #     # 1. Sicherstellen, dass der Kanal gestoppt ist
                        #     mem32[CTRL_TRIG] &= ~(1 << 0) # EN=0
                        #
                        #     # 2. DMA Sniffer konfigurieren (USB-PD-kompatibel)
                        #     # Anfangswert (Seed) setzen
                        #     mem32[SNIFF_DATA] = 0xFFFFFFFF 
                        #     
                        #     # Sniffer aktivieren:
                        #     # SNIFF_EN = 1 (Bit 4)
                        #     # CALC_TYPE = 0x2 (CRC32) (Bits 3:1)
                        #     # OUT_REV = 1 (Bit 0) (WICHTIG für PD-CRC)
                        #     mem32[SNIFF_CTRL] = (1 << 4) | (0x2 << 1) | (1 << 0)
                        #
                        #     # 3. DMA-Transfer konfigurieren
                        #     # Lese-Adresse: Adresse des 'header_data' Buffers
                        #     mem32[READ_ADDR] = uctypes.addressof(data_buffer)
                        #     # Schreib-Adresse: Dummy-Register (wir wollen nur sniffe, nicht schreiben)
                        #     mem32[WRITE_ADDR] = SIO_FIFO_W
                        #     # Anzahl der Bytes, die gelesen werden sollen
                        #     mem32[TRANS_COUNT] = len(data_buffer)
                        #
                        #     # 4. DMA-Kanal starten (CTRL_TRIG)
                        #     # EN=1, INCR_READ=1, DATA_SIZE=0 (Byte)
                        #     # Chain to self (optional, aber gut zum Aufräumen)
                        #     mem32[CTRL_TRIG] = (1 << 0) | (1 << 2) | (0 << 3) | (chan << 11)
                        #
                        #     # 5. Warten, bis DMA fertig ist (BUSY-Bit pollen)
                        #     # (In einer echten App würde man IRQs nutzen)
                        #     while (mem32[CTRL_TRIG] >> 24) & 1:
                        #         pass # Warte...
                        #
                        #     # 6. Ergebnis aus dem Sniffer-Register lesen
                        #     result_crc = mem32[SNIFF_DATA]
                        #     return result_crc
                        #
                        # # In MicroPython wäre der Aufruf dann:
                        # # crc_calculated = get_hw_crc32(header_data)
                        #
                        # --- ENDE: Auskommentierter MicroPython-Code ---
                        
                        
                        # In CircuitPython MÜSSEN wir die langsame Software-Version verwenden:
                        crc_calculated = calculate_crc32(header_data)
                        
                        if crc_received != crc_calculated:
                            print(f"❌ CRC-Fehler! Empf: {crc_received:X} Berech: {crc_calculated:X}")
                            state = STATE_HUNTING_SOP
                            continue
                            
                        # --- NACHRICHT IST GÜLTIG ---
                        
                        # --- HIER SCHEITERT PYTHON AN DER ECHTZEIT ---
                        # Die _send_goodcrc() MUSS innerhalb von 1.5ms erfolgen.
                        # Die Dekodierung und CRC-Prüfung in Python hat
                        # bereits viel länger gedauert.
                        self._send_goodcrc() # Zu langsam!
                        
                        # Nachricht parsen und zurückgeben
                        header = struct.unpack('<H', header_data[:2])[0]
                        data = header_data[2:]
                        num_obj = (header >> 12) & 0x7
                        msg_type = header & 0x1F
                        
                        # Wir haben eine Nachricht, zurück zum SOP-Such-Status
                        state = STATE_HUNTING_SOP 
                        return num_obj, msg_type, data, True
                        
                except MemoryError:
                    print("Speicherfehler bei EOP-Suche, setze zurück.")
                    bit_buffer = []
                    state = STATE_HUNTING_SOP
            
            time.sleep(0.0001) # Kurze Pause, um Puffer füllen zu lassen

        return None, None, None, False # Timeout

    def request_voltage(self, target_voltage_mv=15000):
        """
        Führt eine (theoretische) Spannungs-Aushandlung durch.
        Wird am GoodCRC-Handshake scheitern.
        """
        
        print(f"\n🚀 Starte Aushandlung für {target_voltage_mv / 1000}V...")
        print("⏳ Warte auf Source_Capabilities vom Netzteil...")
        
        # read_message() ist jetzt ein echter (langsamer) Dekodierer
        num_obj, msg_type, data, ok = self.read_message(timeout=5.0)

        if not ok or msg_type != MESSAGE_TYPES.get("Source_Capabilities"):
            print("❌ Timeout oder unerwartete Nachricht empfangen.")
            return

        print_parsed_message(num_obj, msg_type, data)
        
        # Suche nach dem passenden PDO
        found_pdo_index = -1
        for i in range(num_obj):
            pdo = struct.unpack('<I', data[i*4 : (i+1)*4])[0]
            if (pdo >> 30) == 0b00:
                voltage_mv = ((pdo >> 10) & 0x3FF) * 50
                if voltage_mv == target_voltage_mv:
                    found_pdo_index = i + 1 # Position ist 1-basiert
                    break
        
        if found_pdo_index != -1:
            print(f"\n🎯 Passendes PDO an Position {found_pdo_index} gefunden. Sende Request...")
            rdo_data = (found_pdo_index << 28) | (150 << 10) | 150 # 1.5A
            request_msg = build_message(MESSAGE_TYPES.get("Request"), 1, struct.pack('<I', rdo_data))
            
            # send_message() sendet jetzt ein volles Paket UND wartet auf GoodCRC
            if self.send_message(request_msg):
                print("Request wurde mit GoodCRC bestätigt.")
                # TODO: Jetzt auf "Accept" und "PS_RDY" warten
                print("\n🎉 Mission (theoretisch) erfolgreich.")
            else:
                print("\n❌ Netzteil hat Request nicht mit GoodCRC bestätigt.")
        else:
            print(f"\n❌ Kein passendes PDO für {target_voltage_mv / 1000}V im Angebot gefunden.")


# --- Hauptlogik ---

pd_broker = None
try:
    pd_broker = USBPDBroker(RX_PIN, TX_PIN)

    # --- MODUS AUSWÄHLEN ---
    
    # Modus 1: Als (langsamer) Sniffer mit Protokoll-Dekodierung starten.
    # pd_broker.read_message(timeout=60.0) 

    # Modus 2: Als (theoretischer) Strombezüger agieren.
    pd_broker.request_voltage(15000)

except KeyboardInterrupt:
    print("\nBenutzer hat Programm beendet.")
except Exception as e:
    print(f"\nEin kritischer Fehler ist aufgetreten: {e}")
finally:
    if pd_broker:
        pd_broker.deinit()
