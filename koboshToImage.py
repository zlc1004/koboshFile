import PIL.Image
import PIL.ImageColor
newline="ff"
def intToHex(num):
    out=str(hex(num))[2:]
    if out=="ff" or out=="fe" or out=="fd":
        out="fc"
    return ("0"+out if len(out)==1 else out)
def hexToInt(num):
    return int(num,16)//1
def datToBy2(data):
    out=[]
    for i in range(0,len(data),2):
        out.append(data[i]+data[i+1])
    return out
def datToBy3(data):
    out=[]
    for i in range(0,len(data),3):
        out.append(data[i]+data[i+1]+data[i+2])
    return out
def splitBy(data,split):
    out=[]
    tmp=[]
    for i in data:
        if i==split:
            out.append(tmp)
            tmp=[]
        else:    
            tmp.append(i)
    if tmp==[]:
        pass
    else:
        out.append(tmp)
    return out

with open("image.kobosh","rb") as f:
    data=f.read()
data=data.hex()
width=""
widthSkip=False
widthDone=False
height=""
for i in range(len(data)):
    da=data[i]
    if widthSkip:
        widthSkip=False
        continue
    if data[i:i+2]=="fe":
        if not widthDone:
            widthDone=True
            widthSkip=True
            continue
        if widthDone:
            data=data[i+2:]
            break
    if not widthDone:
        width+=da
    if widthDone:
        height+=da

width=hexToInt(width)
height=hexToInt(height)
print(width,height)

print(data[:10])
data=datToBy2(data)
print(data[:10])
print(len(data))
data=datToBy3(data)
print(len(data))
print(data[:10])

imgData=[]

for rgb in data:
    imgData.append(PIL.ImageColor.getcolor("#"+rgb, "RGB"))

image=PIL.Image.new("RGB",(width,height))
image.putdata(imgData)
image.save("imageOut.png")

