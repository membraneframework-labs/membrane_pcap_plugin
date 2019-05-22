# Membrane.Element.LiveAudioMixer

## Warning: this element is experimental!

The element is a simple mixer that combines audio from different sources.
It is designed for use as a live source, meaning it will produce an audio stream
even if some (or all) of the sources fail to provide enough data.

## Installation

Add the following line to your `deps` in `mix.exs`.  Run `mix deps.get`.

```elixir
def deps do
  [
    {:membrane_element_live_audiomixer, github: "membraneframework/membrane-element-live-audiomixer"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)

## Copyright and License

Copyright 2019, [Software Mansion](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=membrane)

[![Software Mansion](https://membraneframework.github.io/static/logo/swm_logo_readme.png)](https://swmansion.com/?utm_source=git&utm_medium=readme&utm_campaign=membrane)

Licensed under the [Apache License, Version 2.0](LICENSE)
