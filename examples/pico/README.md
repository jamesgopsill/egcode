# Using egcode on the Raspberry Pico 2W

This folder contains a demonstration of how to use `egcode` in a `no_std` microcontroller setting which is where you will mostly likely decrypt gcode to be procssed by the CNC machine (e.g., a 3D printer). It also provides an example of how you can take advantage of the hardware SHA processor to speed offload and speed up the SHA calculations. You will need a Pico 2W to hand and have installed `probe-rs` and have a pico probe to flash the device.

You can run the demo by cloning the repo and `cd`ing into the directory and running:

```
cargo run
```

This will run the code in `debug` mode and will run quite slowly. To show at full speed use:

```
cargo run --release 
```
