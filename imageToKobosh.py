import PIL.Image
newline="ff"
def intToHex(num):
    out=str(hex(num))[2:]
    if out=="ff" or out=="fe" or out=="fd":
        out="fc"
    return ("0"+out if len(out)==1 else out)
def datTo2d(data,width):
    return [data[i:i+width] for i in range(0,len(data),width)]
image=PIL.Image.open("image.png")
pixels=list(image.getdata())
pixels=datTo2d(pixels,image.width)
medata=(str(hex(image.width))[2:]+"fe"+str(hex(image.height))[2:]+"fe")
out=[]
for row in pixels:
    tmp=""
    for pixel in row:
        tmp+=(intToHex(pixel[0])+intToHex(pixel[1])+intToHex(pixel[2]))
    out.append(tmp)
out="".join(out)
out=medata+out
out=bytes.fromhex(out)
with open("image.kobosh","wb") as f:
    f.write(out)