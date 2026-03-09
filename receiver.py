import serial

port = "COM11"   # change to your ESP8266 port
baud = 9600

ser = serial.Serial(port, baud)

print("Receiving IoT traffic...")

while True:
    data = ser.readline().decode().strip()
    print("Traffic:", data)
