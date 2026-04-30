import { NeuralNoise } from "@/components/ui/neural-noise";

export default function NeuralDemo() {
   return (
    <div className="relative flex h-full min-h-[400px] w-full flex-col items-center justify-center overflow-hidden rounded-xl border bg-background">
      <NeuralNoise />
      <span className="pointer-events-none absolute z-10 text-center text-7xl leading-none font-semibold tracking-tighter whitespace-pre-wrap text-rose-500">
        Neural Noise
      </span>
    </div>
  )
}
