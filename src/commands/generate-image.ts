/**
 * CLI command for generating images.
 * Used by Claude via the image-generator skill.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import {
	generateImage,
	getEstimatedCost,
	isImageGenerationAvailable,
} from "../services/image-generation.js";

const logger = getChildLogger({ module: "cmd-generate-image" });

type ImageSize = "auto" | "1024x1024" | "1536x1024" | "1024x1536";

export type GenerateImageOptions = {
	size?: ImageSize;
	quality?: "low" | "medium" | "high";
	verbose?: boolean;
};

export function registerGenerateImageCommand(program: Command): void {
	program
		.command("generate-image")
		.description("Generate an image using GPT Image 1.5")
		.argument("<prompt>", "Text description of the image to generate")
		.option("-s, --size <size>", "Image size: auto, 1024x1024, 1536x1024, 1024x1536", "1024x1024")
		.option("-q, --quality <quality>", "Quality tier: low, medium, high", "medium")
		.action(async (prompt: string, opts: GenerateImageOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			try {
				if (!isImageGenerationAvailable()) {
					console.error("Error: Image generation not available. Set OPENAI_API_KEY.");
					process.exit(1);
				}

				const size = validateSize(opts.size);
				const quality = validateQuality(opts.quality);

				if (verbose) {
					const cost = getEstimatedCost(size, quality);
					console.log(`Generating image with ${quality} quality at ${size}...`);
					console.log(`Estimated cost: $${cost.toFixed(2)}`);
				}

				const result = await generateImage(prompt, {
					size,
					quality,
				});

				// Output in a format that's easy to parse
				console.log(`Generated image saved to: ${result.path}`);
				console.log(`Size: ${(result.sizeBytes / 1024).toFixed(1)} KB`);
				console.log(`Model: ${result.model}`);

				if (result.revisedPrompt && verbose) {
					console.log(`Revised prompt: ${result.revisedPrompt}`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "generate-image command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}

function validateSize(size?: string): ImageSize {
	const valid: ImageSize[] = ["auto", "1024x1024", "1536x1024", "1024x1536"];
	if (size && valid.includes(size as ImageSize)) {
		return size as ImageSize;
	}
	return "1024x1024";
}

function validateQuality(quality?: string): "low" | "medium" | "high" {
	const valid = ["low", "medium", "high"];
	if (quality && valid.includes(quality)) {
		return quality as "low" | "medium" | "high";
	}
	return "medium";
}
