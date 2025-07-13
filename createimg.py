import PIL.Image,random
image=PIL.Image.new("RGB",(1000,1000))
image.putdata([tuple(random.randint(0,255) for _ in range(3)) for _ in range(1000*1000)])
image.save("image.png")