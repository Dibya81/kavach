import os

def check_dataset(dataset_path):
    for split in ['train', 'valid', 'test']:
        img_dir = os.path.join(dataset_path, split, 'images')
        label_dir = os.path.join(dataset_path, split, 'labels')
        
        if not os.path.exists(img_dir) or not os.path.exists(label_dir):
            print(f"ERROR: {split} directories missing.")
            continue
            
        images = set([os.path.splitext(f)[0] for f in os.listdir(img_dir) if f.endswith(('.jpg', '.png', '.jpeg'))])
        labels = set([os.path.splitext(f)[0] for f in os.listdir(label_dir) if f.endswith('.txt')])
        
        print(f"--- {split} ---")
        print(f"Images: {len(images)}")
        print(f"Labels: {len(labels)}")
        
        missing_labels = images - labels
        missing_images = labels - images
        
        if missing_labels:
            print(f"WARNING: {len(missing_labels)} images missing labels.")
        if missing_images:
            print(f"WARNING: {len(missing_images)} labels missing images.")

dataset_path = "/Users/dibyabhusal/Desktop/kavach/in-aircraft weapon detection.v1i.yolov12"
check_dataset(dataset_path)
