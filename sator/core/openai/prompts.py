from typing import Union, List, Dict

from sator.core.openai.utils import remove_links, remove_html_tags, remove_code_blocks

REQUEST_TOKENS_LIMIT = 2000
GET_REPOSITORY_SOFTWARE_TYPE = [{"role": "system",
                                 "content": "Given the name, description, and read me of a repository, identify its "
                                            "Software Type. The Software Type can be either: Web Application, Utility, "
                                            "Server, Operating System, Browser, Framework, or Middleware. 'Web "
                                            "Application' are web-based/cloud-based software used for content "
                                            "management, information management, transactions, and more. 'Utility' are "
                                            "standalone apps including productivity tools, creativity software, "
                                            "antivirus programs, scripts, and non-web clients. 'Server' are system "
                                            "servers such as cloud-based, database, email, proxy, web, FTP, DNS, load "
                                            "balancers, and network monitors. 'Operating System' are firmware, device "
                                            "drivers, virtual machines, and all types of operating systems. 'Browser' "
                                            "are all types of web browsers used to access and navigate websites and "
                                            "web applications. 'Framework' are software components like libraries, "
                                            "plugins, and extensions that provide a foundation for building "
                                            "applications or systems. 'Middleware' are enterprise transaction "
                                            "platforms like message queuing, object storage, and identity management "
                                            "systems that facilitate communication between different software. "
                                            "Respond in this format: {'software_type': 'value'}"}
                                ]


def get_repository_software_type(name: str, description: str, read_me: str, margin: int = 5, prompt: bool = False,
                                 description_size_limit: int = 450, max_allowed_size: int = 450) \
        -> Union[str, List[Dict[str, str]]]:
    messages = GET_REPOSITORY_SOFTWARE_TYPE.copy()
    prompt_size = len(messages[0]['content'])
    max_completion_size = 50

    if len(description) > description_size_limit:
        description = description[:description_size_limit]

    content = f"Name: {name}\nDescription: {description}"
    allowed_size = REQUEST_TOKENS_LIMIT - prompt_size - max_completion_size - len(content) - margin

    # Remove code blocks from read me
    read_me = remove_code_blocks(read_me)
    # Remove HTML elements from read me
    read_me = remove_html_tags(read_me)
    # Remove URLs from the read me
    read_me = remove_links(read_me)

    if allowed_size > max_allowed_size:
        allowed_size = max_allowed_size

    if len(read_me) > allowed_size:
        read_me = read_me[:allowed_size]

    content += f"\nRead me: {read_me}"
    messages.append({"role": "user", "content": content})

    if not prompt:
        return messages

    return "\n".join([f"{m['content']}" for m in messages])
