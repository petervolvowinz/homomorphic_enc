**Homomorphic encryption example over gRPC**

Homomorhic encryption lets us encrypt data and perform mathematical operations on
the encrypted data. This opens up for uses cases where you are able to do calculations and get
results without sharing the actual value of your submitted data. This example is using the
traveled distance - odometer - readings , encrypt this and sends this up to the server which calculates
current cost based on cost = fee + rate * traveled-distance. gRPC is used as the transport protocol between client
and server.


```
$ runscript.sh # will open two terminal windows, and build and run the example.
```





