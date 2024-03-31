//function to display all of the sports that you can pick from
function sportsOffered(){
    var array = ["Basketball", "Soccer", "Volleyball","Hockey","Football"];
    var dropdown = document.getElementById("dropdown");
    for(let i=0;i<array.length;i++){
        var option = document.createElement("li");
        option.textContent = array[i];
        dropdown.appendChild(option);
    }
}
//function to start the chat box at the bottom
document.addEventListener('DOMContentLoaded', function() {
    var scrollContainer = document.querySelector('.chat-room');
    
    // Scroll to the bottom on page load
    scrollContainer.scrollTop = scrollContainer.scrollHeight;
  
    // Additional code for dynamic content or user interaction
  });
  
window.onload = sportsOffered;

function updateChatRoom(messages) {
    const request = new XMLHttpRequest();
    request.onreadystatechange = function() {
        if (this.readyState === 4 && this.status === 200){
            const message = JSON.parse(this.response);
            messages = message['messages'];
            likes = message['likes'];
            var chatRoom = document.getElementById('chat-room');
            chatRoom.innerHTML = ''; // Clear existing messages

            // Append the new messages to the chat room
            messages.forEach(function(message) {
                let count = 0;
                likes.forEach(function(like){
                    var messageId = message[0];
                    var likeId = like[0];
                    if(messageId == likeId){
                        count = like[1];
                    }
                })
                var div_element = document.createElement('div');
                div_element.className = "chat-chat";
                //form creation for the post request
                var like_form = document.createElement('form');
                like_form.setAttribute('method','POST');
                like_form.setAttribute('action','/like');
                like_form.className = "chat-chat";
                div_element.appendChild(like_form);

                var id_field = document.createElement('input');
                id_field.setAttribute('type','hidden');
                id_field.setAttribute('value',message[0]);
                id_field.setAttribute('name','id');
                like_form.appendChild(id_field);

                var paragraph = document.createElement('p');
                paragraph.className = 'user-message';
                paragraph.textContent = message[1] + ' | Team ' + message[2] + ': ' + message[3];
                like_form.appendChild(paragraph);
                //adding the like features
                var like_button = document.createElement('button');
                like_button.className = 'like-button';
                like_button.textContent = 'Like\uD83D\uDC4D';
                like_button.setAttribute('type','submit');
                like_form.appendChild(like_button);
                var like_count = document.createElement('p');
                like_count.className = 'like-count';
                like_count.textContent = "Likes: " + count;
                like_form.appendChild(like_count);
                chatRoom.appendChild(div_element);

                //adding the hidden elements to be issued during post request
            });
            var scrollContainer = document.querySelector('.chat-room');
                
                // Scroll to the bottom on page load
            scrollContainer.scrollTop = scrollContainer.scrollHeight;
        }
    }
    request.open("GET","/chat-update");
    request.send();
}

function pollChat() {
   updateChatRoom(); 
}
setInterval(pollChat, 2000);
pollChat();