/**
 * Image generation service using OpenAI GPT Image API.
 * Uses GPT Image 1.5 (December 2025).
 */

import fs from "node:fs";

import { type ImageGenerationConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { saveMediaBuffer } from "../media/store.js";
import { getOpenAIClient, isOpenAIConfigured, isOpenAIConfiguredSync } from "./openai-client.js";

const logger = getChildLogger({ module: "image-generation" });

/** Supported image sizes for GPT Image 1.5 */
type ImageSize = "auto" | "1024x1024" | "1536x1024" | "1024x1536";

/**
 * Image generation options.
 */
export type ImageGenerationOptions = {
	/** Image size. Default: 1024x1024 */
	size?: ImageSize;
	/** Quality tier: low, medium, high. Default: medium */
	quality?: "low" | "medium" | "high";
	/** Number of images to generate. Default: 1 */
	n?: number;
};

/**
 * Generated image result.
 */
export type GeneratedImage = {
	/** Local file path to the saved image */
	path: string;
	/** Revised prompt (if the model modified it) */
	revisedPrompt?: string;
	/** Image size in bytes */
	sizeBytes: number;
	/** Model used */
	model: string;
	/** Quality setting used */
	quality: string;
};

/**
 * Default image generation config.
 */
const DEFAULT_CONFIG: ImageGenerationConfig = {
	provider: "gpt-image",
	model: "gpt-image-1.5",
	size: "1024x1024",
	quality: "medium",
	maxPerHourPerUser: 10,
	maxPerDayPerUser: 50,
};

const SUPPORTED_SIZES: ImageSize[] = ["auto", "1024x1024", "1536x1024", "1024x1536"];

/**
 * Generate an image from a text prompt.
 *
 * @param prompt - Text description of the image to generate
 * @param options - Generation options
 * @returns Generated image with local path and metadata
 */
export async function generateImage(
	prompt: string,
	options?: ImageGenerationOptions,
): Promise<GeneratedImage> {
	if (!(await isOpenAIConfigured())) {
		throw new Error("OpenAI API key not configured for image generation");
	}

	const config = loadConfig();
	const imageConfig = {
		...DEFAULT_CONFIG,
		...config.imageGeneration,
		...options,
	};

	if (imageConfig.provider === "disabled") {
		throw new Error("Image generation is disabled in config");
	}

	const client = await getOpenAIClient();
	const model = imageConfig.model ?? "gpt-image-1.5";
	const size = (imageConfig.size ?? "1024x1024") as ImageSize;
	const quality = imageConfig.quality ?? "medium";

	// Validate size
	if (!SUPPORTED_SIZES.includes(size)) {
		throw new Error(
			`Image size "${size}" is not supported. Use one of: ${SUPPORTED_SIZES.join(", ")}.`,
		);
	}

	logger.info({ prompt: prompt.slice(0, 100), model, size, quality }, "generating image");

	const startTime = Date.now();

	try {
		const response = await client.images.generate({
			model,
			prompt,
			size,
			quality,
			n: 1,
			output_format: "png",
		});

		const durationMs = Date.now() - startTime;

		// Handle response - SDK may return Stream or ImagesResponse
		if (!("data" in response) || !response.data?.[0]) {
			throw new Error("No image data in response");
		}

		const imageData = response.data[0];
		const base64 = imageData.b64_json;

		if (!base64) {
			throw new Error("No base64 image data in response");
		}

		// Save using centralized media store
		const buffer = Buffer.from(base64, "base64");
		const saved = await saveMediaBuffer(buffer, {
			mimeType: "image/png",
			category: "generated",
			extension: ".png",
		});

		const stat = await fs.promises.stat(saved.path);

		logger.info(
			{
				model,
				size,
				quality,
				durationMs,
				sizeBytes: stat.size,
				revisedPrompt: imageData.revised_prompt?.slice(0, 50),
			},
			"image generated successfully",
		);

		return {
			path: saved.path,
			revisedPrompt: imageData.revised_prompt,
			sizeBytes: stat.size,
			model,
			quality,
		};
	} catch (error) {
		logger.error({ prompt: prompt.slice(0, 100), error }, "image generation failed");
		throw error;
	}
}

/**
 * Generate multiple images from a prompt.
 */
export async function generateImages(
	prompt: string,
	count: number,
	options?: ImageGenerationOptions,
): Promise<GeneratedImage[]> {
	const results: GeneratedImage[] = [];

	// Generate one at a time to handle failures gracefully
	for (let i = 0; i < count; i++) {
		try {
			const image = await generateImage(prompt, options);
			results.push(image);
		} catch (error) {
			logger.error({ index: i, error }, "failed to generate image in batch");
			// Continue with remaining images
		}
	}

	return results;
}

/**
 * Check if image generation is available.
 * Uses sync check for env/config; keychain key will be found at runtime.
 */
export function isImageGenerationAvailable(): boolean {
	const config = loadConfig();

	if (config.imageGeneration?.provider === "disabled") {
		return false;
	}

	return isOpenAIConfiguredSync();
}

/**
 * Get estimated cost for image generation.
 * Based on December 2025 pricing for GPT Image 1.5.
 */
export function getEstimatedCost(size: ImageSize, quality: "low" | "medium" | "high"): number {
	const pricing: Record<string, Record<string, number>> = {
		auto: { low: 0.01, medium: 0.04, high: 0.17 },
		"1024x1024": { low: 0.01, medium: 0.04, high: 0.17 },
		"1536x1024": { low: 0.02, medium: 0.08, high: 0.25 },
		"1024x1536": { low: 0.02, medium: 0.08, high: 0.25 },
	};

	return pricing[size]?.[quality] ?? 0.04;
}
