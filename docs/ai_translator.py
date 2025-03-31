#!/usr/bin/env python3

import os
import shutil
import pathlib

import openai


class AITranslator:
    """AI Translator class"""

    def __init__(self, api_key: str):
        """Initialize the translator with the given API key"""
        self.OpenAIClient = openai.OpenAI(api_key=api_key)

        with open('cs/vocabulary.txt', 'r', encoding='utf-8') as f:
            self.Vocabulary = f.read()


    def _prepare_translation_prompt(self, filename: pathlib.Path, previous_translation: str) -> str:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()

        """Prepare the prompt for the LLM"""
        prompt = f"""Translate the Markdown content from English to Czech.
The content is part of technical documentation using Material for MkDocs framework.

The content starts with the markdown header "--- START OF CONTENT ---" and ends with the marker "--- END OF CONTENT ---".
Don't translate or include markers in the output.

Please maintain:
1. All Markdown formatting
2. Code blocks and their language specifiers
3. Material for MkDocs specific features (admonitions, tabs, etc.)
4. Proper Czech technical terminology
5. Don't change any links or references to other files, they must stay in English
6. Don't translate any configuration, JSON, YAML, etc.; the only exception are comments.

Translate the content while preserving all formatting and special features.

Vocabulary:
{self.Vocabulary}

--- START OF CONTENT ---
{content}
--- END OF CONTENT ---
"""
        if previous_translation:
            prompt += f"""
Previous translation, use it as a reference:
{previous_translation}
"""

        return prompt

    def translate_content(self, filename: pathlib.Path, previous_translation: str) -> str:
        """Translate content using OpenAI API"""
        prompt = self._prepare_translation_prompt(filename, previous_translation)

        try:
            # Create the file attachment
            response = self.OpenAIClient.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a professional technical translator specializing in software documentation."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            )

            translation = response.choices[0].message.content
            return translation

        except Exception as e:
            print(f"Error during translation: {e}")
            raise


    def process_file(self, source_path: pathlib.Path, target_path: pathlib.Path):
        """Process a single markdown file"""
        print(f"Processing {source_path}...")

        if os.path.exists(target_path):
            previous_translation = open(target_path, 'r', encoding='utf-8').read()
        else:
            previous_translation = None

        # Translate content
        translated_content = self.translate_content(source_path, previous_translation)

        # Ensure target directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Write translated content
        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(translated_content)


    def process_directory(self, source_dir: pathlib.Path, target_dir: pathlib.Path):
        """Process all markdown files in the directory"""
        source_dir = pathlib.Path(source_dir)
        target_dir = pathlib.Path(target_dir)

        # Create target directory if it doesn't exist
        target_dir.mkdir(parents=True, exist_ok=True)

        files = list(source_dir.iterdir())
        files.sort(key=lambda x: (not x.name.endswith('index.md'), x))

        dirs = []

        # Process all markdown files
        for source_path in files:
            if source_path.is_dir():
                dirs.append(source_path)
                continue

            if source_path.suffix == '.md':
                rel_path = source_path.relative_to(source_dir)
                target_path = target_dir / rel_path
                self.process_file(source_path, target_path)

            else:
                rel_path = source_path.relative_to(source_dir)
                target_path = target_dir / rel_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, target_path)


        for source_path in dirs:
            rel_path = source_path.relative_to(source_dir)
            target_path = target_dir / rel_path
            self.process_directory(source_path, target_path)


def main():
    api_key = os.environ['OPENAI_API_KEY']
    translator = AITranslator(api_key)

    source_dir = pathlib.Path('en/docs')
    target_dir = pathlib.Path('cs/docs')

    translator.process_directory(source_dir, target_dir)
    print("Translation completed successfully!")


if __name__ == '__main__':
    main()
